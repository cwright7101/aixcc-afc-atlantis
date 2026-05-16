import os
import time
import yaml
import redis
import requests
import threading
import subprocess
import json

from uuid import UUID
from pathlib import Path
from pydantic import BaseModel
from typing import Optional, Dict

from crs_webserver.my_crs.crs_manager.k8s_manager import K8sManager
from crs_webserver.my_crs.crs_manager.budget import (
    allocate_llm_budget,
    allocate_vcpu_budget,
    return_vcpu_budget,
    get_vcpu_basic_budget,
)
from crs_webserver.my_crs.crs_manager.crs_types import TaskStatus
from crs_webserver.my_crs.task_server.models.types import (
    TaskDetail,
    SourceType,
    TaskType,
)

from .redis_util import RedisUtil
from .cp_template import TEMPLATES
from .cp import CP
from .llm_key import (
    create_crs_multilang_llm_key,
    create_crs_patch_llm_key,
    create_crs_java_llm_key,
    create_crs_userspace_llm_key,
)
from libCRS import install_otel_logger

install_otel_logger()

from loguru import logger
from crs_webserver.my_crs.crs_manager.log_config import setup_logger, setup_filebeat

setup_logger()

TARBALL_DIR = Path("/tarball-fs")
LOCAL_TARBALL_DIR = Path("/tarball-local")
SHARED = Path("/shared-crs-fs")
VERIFIER_HEAD_WORKDIR = Path(os.getenv("VERIFIER_HEAD_WORKDIR"))
VERIFIER_BASE_WORKDIR = Path(os.getenv("VERIFIER_BASE_WORKDIR"))


def run(cmd: list, env: Optional[Dict[str, str]] = None):
    cmd = list(map(str, cmd))
    logger.info(" ".join(cmd))
    try:
        ret = subprocess.run(
            cmd,
            check=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        return ret
    except:
        pass


def rsync(src: Path, dst: Path):
    if src.is_dir():
        src = f"{src}/."
    cmd = ["rsync", "-a", src, dst]
    while True:
        ret = run(cmd)
        if ret.returncode == 0:
            return ret
        else:
            logger.info("Retry rsync..")
            time.sleep(1)


def tar(src: Path, dst: Path):
    cmd = ["tar", "--use-compress-program=pigz", "-cv"]
    cmd += ["-f", dst, "-C", src, "."]
    run(cmd)


def download_tar(url: str, dst: Path):
    cmd = ["wget", url, "-O", dst]
    run(cmd)


CP_NODE_POOL_NAME = os.getenv("CP_NODE_POOL_NAME")


class CPManager:
    def __init__(self):
        self.redis = RedisUtil()
        self.k8s = K8sManager(self.redis.client, TEMPLATES)
        self.task_id = os.getenv("TASK_ID")
        self.task_detail = self.redis.get_task_detail(UUID(self.task_id))
        self.is_delta_mode = self.task_detail.type.value == TaskType.TaskTypeDelta.value
        self.language = None
        self.download_tarball_dir = None
        self.local_download_tarball_dir = None
        self.javacrs_tarball_dir = None
        self.llm_budget = allocate_llm_budget(self.task_id)

        self.multilang_tarball = TARBALL_DIR / self.task_id / "crs-multilang"
        os.makedirs(self.multilang_tarball, exist_ok=True)
        self.userspace_vcpu_spend = 0
        cp_mgr_node_size = os.getenv("CP_MGR_VM_SIZE", "Standard_D32ds_v6")
        if cp_mgr_node_size == "":
            cp_mgr_node_size = "Standard_D32ds_v6"
        cp_mgr_node_vcpu_cnt = int(cp_mgr_node_size.split("_")[1][1:].split("d")[0])

        crs_patch_node_size = os.getenv("CRS_PATCH_VM_SIZE", "Standard_D32ds_v6")
        if crs_patch_node_size == "":
            crs_patch_node_size = "Standard_D32ds_v6"
        self.crs_patch_node_size = crs_patch_node_size
        crs_patch_node_vcpu_cnt = int(
            crs_patch_node_size.split("_")[1][1:].split("d")[0]
        )
        CRS_PATCH_NODE_CNT = 5

        # 3 nodes: cp_mgr, crs-sarif, crs-multilang-cp-lvl
        # 5 nodes: crs-patch
        self.cp_mgr_node_vcpu_spend = self.__get_running_hours() * (
            3 * cp_mgr_node_vcpu_cnt + crs_patch_node_vcpu_cnt * CRS_PATCH_NODE_CNT
        )
        self.info(
            f"CP-Manager + CRS-sarif + CRS-patch vCPU spend: {self.cp_mgr_node_vcpu_spend}"
        )

        self.quota = int(os.getenv("QUOTA_PER_CP", "1000"))
        self.info(f"Given Quota: {self.quota}")
        self.quota -= (
            3 * cp_mgr_node_vcpu_cnt + crs_patch_node_vcpu_cnt * CRS_PATCH_NODE_CNT
        )
        self.info(
            f"Quota after deducting CP-Manager + CRS-sarif + CRS-patch: {self.quota}"
        )

    def error(self, msg):
        logger.error(f"[CPManager][{self.task_id}] {msg}")

    def info(self, msg):
        logger.info(f"[CPManager][{self.task_id}] {msg}")

    def launch(self):
        self.info("Launch")

        if self.task_detail.is_binary_only:
            self.info(
                "Binary-only task detected; dispatching to binary intake "
                "(skipping OSS-Fuzz build, crs-multilang, crs-sarif, crs-patch, crs-java)."
            )
            from .binary_intake import run_binary_intake

            run_binary_intake(self.task_detail, self.task_id)
            return

        def build():
            return self.__build()

        t = threading.Thread(target=build)
        t.start()
        self.__launch_nodes()
        t.join()

    def __get_running_hours(self):
        deadline = int(self.task_detail.deadline / 1000)
        now = int(time.time())
        running_hours = (deadline - now) / 3600
        if running_hours < 0:
            self.error("Deadline is in the past")
            exit(1)
        self.info(f"Running for {running_hours} hours + 0.2hours (buffer)")
        running_hours += 0.2
        return running_hours

    def __calculate_node_size(self, harness_cnt: int, is_jvm: bool):
        self.info(f"Calculate node vm size for {harness_cnt} harnesses")
        running_hours = self.__get_running_hours()

        vcpu_budget = allocate_vcpu_budget(self.task_id)
        self.info(f"Have {vcpu_budget} vCPU hours budget")
        vcpu_budget -= self.cp_mgr_node_vcpu_spend
        self.info(
            f"After deducting CP-Manager + CRS-sarif + CRS-patch vCPU spend: {vcpu_budget}"
        )
        vcpu_cnt = int(vcpu_budget / running_hours)
        self.info(
            f"Have {vcpu_budget} vCPU hours budget => {vcpu_cnt} vCPUs during {running_hours} hours"
        )
        quota = self.quota
        if is_jvm:
            vcpu_cnt = int(vcpu_cnt / 2)
            quota = quota / 2
            self.info(
                f"=> {vcpu_cnt} vCPUs, {quota} quota per CRS (CRS-multilang + CRS-java)"
            )
        else:
            userspace_vcpu_cnt = int(self.userspace_vcpu_spend / running_hours)
            vcpu_cnt -= userspace_vcpu_cnt
            self.info(
                f"=> {vcpu_cnt} vCPUs, {quota} quota per CRS-multilang, {userspace_vcpu_cnt} vCPUs per CRS-userspace"
            )
        size = 0
        for size in [128, 96, 64, 48, 32, 16, 8, 4]:
            if size * harness_cnt <= vcpu_cnt and size * harness_cnt <= quota:
                break
        spend = int(size * running_hours * harness_cnt)
        if is_jvm:
            spend = spend * 2
            self.quota -= size * harness_cnt * 2
        else:
            spend += self.userspace_vcpu_spend
            self.quota -= size * harness_cnt
        return_vcpu_budget(self.task_id, spend)
        ret = f"Standard_D{size}ds_v6"
        self.info(
            f"Allocate {ret} for {harness_cnt} harnesses for {running_hours} hours (CRS-multilang + CRS-java/CRS-userspace)"
        )
        self.info(f"Quota after allocating everything: {self.quota}")
        return ret

    def __calculate_userspace_nodepool(self) -> (str, int):
        self.info("Calculate userspace node cnt")
        basic_budget = get_vcpu_basic_budget()
        userspace_vcpu_budget = (basic_budget - self.cp_mgr_node_vcpu_spend) / 2
        running_hours = self.__get_running_hours()
        userspace_node_size = int(os.getenv("USERSPACE_NODE_SIZE", "64"))
        userspace_node_max_cnt = int(os.getenv("USERSPACE_MAX_NODE_CNT", "4"))
        userspace_node_max_based_on_quota = int(self.quota / userspace_node_size)
        node_cnt = int(userspace_vcpu_budget / running_hours / userspace_node_size)
        node_cnt = min(
            node_cnt, userspace_node_max_cnt, userspace_node_max_based_on_quota
        )
        if node_cnt <= 0:
            node_cnt = 1
            self.info("No enough vCPU budget for userspace but allocate 1 node")

        self.info(
            f"Basic budget: {basic_budget}, crs-userspace budget: {userspace_vcpu_budget}, userspace_node_max_cnt: {userspace_node_max_cnt}"
        )
        self.info(
            f"running hours: {running_hours}, userspace_node_size: {userspace_node_size}, node_cnt: {node_cnt}"
        )
        self.userspace_vcpu_spend = int(userspace_node_size * node_cnt * running_hours)
        self.info(f"userspace_vcpu_spend: {self.userspace_vcpu_spend}")
        node_size = f"Standard_D{userspace_node_size}ds_v6"
        self.quota -= node_cnt * userspace_node_size
        self.info(f"Quota after deducting userspace: {self.quota}")
        return (node_size, node_cnt)

    def __launch_nodes(self):
        if self.redis.is_launched_before():
            self.info("Skip launching nodes because launched before, cp-mgr rebooted?")
            return

        def launch_cp_levels():
            try:
                self.__launch_crs_multilang_cp_levels()
            except:
                pass

            language = self.__wait_language()
            self.__launch_crs_sarif(language)

        def launch_crs_patch():
            self.__launch_crs_patch()

        t = threading.Thread(target=launch_cp_levels)
        t.start()

        t1 = threading.Thread(target=launch_crs_patch)
        t1.start()

        language = self.__wait_language()
        is_jvm = language == "jvm"
        t2 = None
        if not is_jvm:
            (node_size, node_cnt) = self.__calculate_userspace_nodepool()
            t2 = threading.Thread(
                target=self.__launch_crs_userspace, args=(node_size, node_cnt)
            )
            t2.start()

        harness_names = self.__wait_harness_names()
        node_size = self.__calculate_node_size(len(harness_names), is_jvm)

        t3 = None
        if is_jvm:
            t3 = threading.Thread(
                target=self.__launch_crs_java, args=(harness_names, node_size)
            )
            t3.start()

        self.__launch_crs_multilang(harness_names, node_size)

        t.join()
        t1.join()
        if t2 != None:
            t2.join()
        if t3 != None:
            t3.join()

    def __launch_crs_multilang(self, harness_names, node_size):
        node_cnt = len(harness_names)
        self.info(f"Request {node_size} typed, {node_cnt} nodes for CRS-multilang")
        multilang_node_pool_name = self.k8s.create_multilang_node_pool(node_size)
        self.info("Launch CRS-multilang")
        self.k8s.deploy_from_template(
            UUID(self.task_id),
            "crs-multilang-nodes",
            multilang_node_pool_name,
            node_cnt,
            self.task_detail,
            self.multilang_tarball,
            harness_names,
            create_crs_multilang_llm_key(self.redis, self.llm_budget),
        )

    def __launch_crs_multilang_cp_levels(self):
        self.info("Launch CRS-multilang-cp-levels")
        self.k8s.deploy_from_template(
            UUID(self.task_id),
            "crs-multilang-cp-levels",
            CP_NODE_POOL_NAME,
            1,
            self.task_detail,
            self.multilang_tarball,
        )

    def __launch_crs_java(self, harness_names, node_size):
        node_cnt = len(harness_names)
        self.info(f"Request {node_size} typed, {node_cnt} nodes for CRS-java")
        java_pool_name = self.k8s.create_java_node_pool(node_size)
        self.info("Launch CRS-java")
        javacrs_tallball_dir = self.__wait_javacrs_tarball_dir()
        self.k8s.deploy_from_template(
            UUID(self.task_id),
            "crs-java-nodes",
            java_pool_name,
            node_cnt,
            self.task_detail,
            self.__wait_download_tarball(),
            javacrs_tallball_dir,
            harness_names,
            create_crs_java_llm_key(self.redis, self.llm_budget),
        )

    def __launch_crs_patch(self):
        self.info("Launch CRS-patch")
        crs_patch_pool_name = self.k8s.create_crs_patch_node_pool(
            self.crs_patch_node_size
        )
        if self.language in ["java", "jvm"]:
            language = "jvm"
        else:
            language = "c"
        self.k8s.deploy_from_template(
            UUID(self.task_id),
            "crs-patch-nodes",
            crs_patch_pool_name,
            5,
            self.task_detail,
            self.__wait_download_tarball(),
            create_crs_patch_llm_key(self.redis, self.llm_budget),
            language,
        )

    def __launch_crs_userspace(self, node_size, node_cnt):
        self.info("Launch CRS-userspace")
        node_pool_name = self.k8s.create_userspace_node_pool(node_size)
        self.__prepare_userspace()

        out_dir = TARBALL_DIR / self.task_id / "crs-userspace"

        self.k8s.deploy_from_template(
            UUID(self.task_id),
            "crs-userspace-nodes",
            node_pool_name,
            node_cnt,
            self.task_detail,
            out_dir,
            node_cnt,
            create_crs_userspace_llm_key(self.redis, self.llm_budget),
        )

    def __launch_crs_sarif(self, language: str):
        self.info("Launch CRS-sarif")
        if self.language in ["java", "jvm"]:
            language = "jvm"
        else:
            language = "c"
        self.k8s.deploy_from_template(
            UUID(self.task_id),
            "crs-sarif-nodes",
            CP_NODE_POOL_NAME,
            1,
            self.task_detail.project_name,
            self.task_id,
            self.download_tarball_dir,
            self.__wait_harness_names(),
            language,
            os.getenv("LITELLM_KEY_CRS_SARIF"),
        )

    def __build(self):
        local, remote = self.__download()
        self.local_download_tarball_dir = local
        self.download_tarball_dir = remote
        focus = self.task_detail.focus
        self.__build_multilang(self.local_download_tarball_dir, focus)
        self.__build_all_sanitizers(self.local_download_tarball_dir, focus)
        self.__build_symcc(self.local_download_tarball_dir, focus)

    def __download(self) -> Path:
        local_tarball_dir = LOCAL_TARBALL_DIR / self.task_id / "task_tarballs"
        remote_tarball_dir = TARBALL_DIR / self.task_id / "task_tarballs"
        os.makedirs(local_tarball_dir, exist_ok=True)
        os.makedirs(remote_tarball_dir, exist_ok=True)
        self.info(f"Download tarballs into {local_tarball_dir}")

        task = self.task_detail
        for src in task.source:
            name = src.type.value
            if name == SourceType.SourceTypeFuzzTooling.value:
                name = "oss-fuzz.tar.gz"
            else:
                name = f"{name}.tar.gz"
            self.info(f"Download {name} from {src.url}")
            download_tar(src.url, local_tarball_dir / name)
            rsync(local_tarball_dir / name, remote_tarball_dir / name)

        return local_tarball_dir, remote_tarball_dir

    def __wait_download_tarball(self):
        self.info("Waiting download tarball dir..")
        while self.download_tarball_dir == None:
            time.sleep(5)
        return self.download_tarball_dir

    def __wait_local_download_tarball(self):
        self.info("Waiting LOCAL download tarball dir..")
        while self.local_download_tarball_dir == None:
            time.sleep(5)
        return self.local_download_tarball_dir

    def __build_multilang(self, tarball_dir: Path, focus: str):
        task_id = self.task_id
        proj_name = self.task_detail.project_name
        out_dir = self.multilang_tarball
        self.info(f"Build {proj_name} for CRS-multilang")
        cmd = ["/app/bin/crs-multilang.py", "build"]
        cmd += ["--target", proj_name]
        cmd += ["--tar-dir", tarball_dir]
        cmd += ["--out-dir", out_dir]
        cmd += ["--focus", focus]
        cmd += ["--registry", os.getenv("REGISTRY")]
        cmd += ["--image-version", os.getenv("IMAGE_VERSION")]
        ret = run(cmd)
        build_log = ""
        try:
            build_log = ret.stderr.decode("utf-8", errors="ignore")
        except:
            pass
        self.info(f"[DONE] Build {proj_name} for CRS-multilang\n{build_log}")

    def __build_symcc(self, tarball_dir: Path, focus: str):
        task_id = self.task_id
        proj_name = self.task_detail.project_name
        out_dir = self.multilang_tarball
        self.info(f"Build {proj_name} for symcc")
        cmd = ["/app/bin/crs-multilang.py", "build"]
        cmd += ["--target", proj_name]
        cmd += ["--tar-dir", tarball_dir]
        cmd += ["--out-dir", out_dir]
        cmd += ["--focus", focus]
        cmd += ["--registry", os.getenv("REGISTRY")]
        cmd += ["--image-version", os.getenv("IMAGE_VERSION")]
        cmd += ["--symcc"]
        ret = run(cmd)
        build_log = ""
        try:
            build_log = ret.stderr.decode("utf-8", errors="ignore")
        except:
            pass
        self.info(f"[DONE] Build {proj_name} for symcc\n{build_log}")

    def __prepare_javacrs_tarball(
        self, proj_dir: Path, repo_dir: Path, build_dir: Path
    ):
        task_id = self.task_id
        out_dir = TARBALL_DIR / task_id / "crs-java"
        os.makedirs(out_dir, exist_ok=True)
        self.javacrs_tarball_dir = out_dir
        self.info(f"Prepare tarballs for CRS-java at {out_dir}")

        conf = self.multilang_tarball / "aixcc_conf.yaml"
        rsync(conf, out_dir / "aixcc_conf.yaml")
        diff = self.multilang_tarball / "ref.diff"
        if diff.exists():
            rsync(diff, out_dir / "ref.diff")

        tar(proj_dir, out_dir / "project.tar.gz")
        tar(repo_dir, out_dir / "repo.tar.gz")
        tar(build_dir, out_dir / "fuzzers.tar.gz")
        (out_dir / "DONE").write_text("DONE")

    def __prepare_userspace(self):
        out_dir = TARBALL_DIR / self.task_id / "crs-userspace"
        out_dir.mkdir(parents=True, exist_ok=True)
        tar_dir = self.__wait_local_download_tarball()
        rsync(tar_dir / "repo.tar.gz", out_dir / "repo.tar.gz")
        rsync(tar_dir / "oss-fuzz.tar.gz", out_dir / "oss-fuzz.tar.gz")

        diff_tar = tar_dir / "diff.tar.gz"
        if diff_tar.exists():
            rsync(diff_tar, out_dir / "diff.tar.gz")

    def __build_all_sanitizers(
        self,
        tarball_dir: Path,
        focus: str,
    ):
        self.info("Build all sanitizers")
        proj_name = self.task_detail.project_name
        head_cp = CP(proj_name, VERIFIER_HEAD_WORKDIR)
        head_cp.prepare_from_tarball(tarball_dir, focus)
        if self.is_delta_mode:
            base_cp = CP(proj_name, VERIFIER_BASE_WORKDIR, False)
            base_cp.prepare_from_tarball(tarball_dir, focus)

        sanitizers = head_cp.get_sanitizers()
        self.info(f"Sanitizers: {sanitizers}")
        to_crs_java_tarball = self.__wait_language() == "jvm"
        first = True
        for sanitizer in sanitizers:
            self.info(
                f"Build {proj_name} under {sanitizer} sanitizer at {VERIFIER_HEAD_WORKDIR}"
            )
            cp = CP(proj_name, VERIFIER_HEAD_WORKDIR / sanitizer, True)
            cp.prepare_from_base(VERIFIER_HEAD_WORKDIR)
            repo_dir, proj_dir, build_dir = cp.build(sanitizer)
            if to_crs_java_tarball:
                self.__prepare_javacrs_tarball(proj_dir, repo_dir, build_dir)
                to_crs_java_tarball = False
            if first:
                cp.pull_runner()
                first = False
            if self.is_delta_mode:
                self.info(
                    f"Delta mode! Build {proj_name} under {sanitizer} sanitizer at {VERIFIER_BASE_WORKDIR}"
                )
                cp = CP(proj_name, VERIFIER_BASE_WORKDIR / sanitizer, False)
                cp.prepare_from_base(VERIFIER_BASE_WORKDIR)
                cp.build(sanitizer)
        self.info(f"[DONE] Build {proj_name} for all sanitizers")

    def __wait_language(self):
        if self.language != None:
            return self.language
        self.info("Waiting language..")
        proj_name = self.task_detail.project_name
        ossfuzz_dir = Path("/app/bin/libs/oss-fuzz")
        conf = ossfuzz_dir / "projects" / proj_name / "project.yaml"
        while not conf.exists():
            time.sleep(5)
        with open(conf) as f:
            conf = yaml.safe_load(f)
            if "language" not in conf:
                self.language = "c++"
            else:
                self.language = conf["language"].strip()
        return self.language

    def __wait_javacrs_tarball_dir(self):
        self.info("Waiting javacrs tarball dir..")
        while self.javacrs_tarball_dir == None:
            time.sleep(5)
        return self.javacrs_tarball_dir

    def __wait_harness_names(self):
        self.info("Waiting harness names..")
        while self.multilang_tarball == None:
            time.sleep(5)
        done = self.multilang_tarball / "DONE"
        while not done.exists():
            time.sleep(5)

        conf = self.multilang_tarball / "aixcc_conf.yaml"
        self.info(f"{conf}:\n" + conf.read_text())
        with open(conf, "r") as conf:
            conf = yaml.safe_load(conf)
            ret = list(map(lambda x: x["name"], conf["harness_files"]))
            self.info(f"Harnesses: {ret}")
            return ret


if __name__ == "__main__":
    setup_filebeat()
    mgr = CPManager()
    mgr.launch()
