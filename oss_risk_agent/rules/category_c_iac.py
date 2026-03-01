from pathlib import Path
from typing import List
import re

from ..core.models import Rule, RiskRecord, Severity

class C5IaCPublicAccessRule(Rule):
    @property
    def category(self) -> str:
        return "C-5"

    @property
    def name(self) -> str:
        return "IaCにおけるパブリックアクセスの許可"

    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        risks = []
        
        target_files = []
        target_files.extend(repo_path.rglob("*.tf"))           # Terraform
        target_files.extend(repo_path.rglob("*.yaml"))         # K8s, CloudFormation
        target_files.extend(repo_path.rglob("*.yml"))          # K8s, CloudFormation
        target_files.extend(repo_path.rglob("*.json"))         # CloudFormation
        
        # S3バケットの公開設定（Terraform）
        tf_s3_public_pattern = re.compile(r"acl\s*=\s*[\"']public-read(-write)?[\"']")
        
        # 0.0.0.0/0 の許可（Terraform / AWS Security Group等）
        cidr_public_pattern = re.compile(r"cidr_blocks\s*=\s*\[\s*[\"']0\.0\.0\.0/0[\"']\s*\]")
        yaml_public_pattern = re.compile(r"cidrBlock:\s*0\.0\.0\.0/0") # CFN yaml
        
        for file in target_files:
            if ".git" in file.parts or "node_modules" in file.parts:
                continue
                
            try:
                with open(file, "r", encoding="utf-8") as f:
                    for i, line in enumerate(f, 1):
                        # Terraform固有チェック
                        if file.suffix == ".tf":
                            if tf_s3_public_pattern.search(line):
                                risks.append(RiskRecord(
                                    category=self.category,
                                    name=self.name,
                                    severity=Severity.HIGH,
                                    description="Terraform設定でS3バケット等にパブリックアクセス(public-read)を許可しています。",
                                    target_file=str(file.relative_to(repo_path)),
                                    line_number=i,
                                    evidence=line.strip()
                                ))
                            if cidr_public_pattern.search(line):
                                risks.append(RiskRecord(
                                    category=self.category,
                                    name=self.name,
                                    severity=Severity.HIGH,
                                    description="Terraform設定でアクセス元を制限せず(0.0.0.0/0)開放しています。",
                                    target_file=str(file.relative_to(repo_path)),
                                    line_number=i,
                                    evidence=line.strip()
                                ))
                                
                        # CloudFormation / Generic YAML JSONチェック
                        elif file.suffix in [".yaml", ".yml", ".json"]:
                            if "0.0.0.0/0" in line:
                                risks.append(RiskRecord(
                                    category=self.category,
                                    name=self.name,
                                    severity=Severity.MEDIUM,
                                    description="IaCテンプレート等でアクセス元を制限せず(0.0.0.0/0)開放している可能性があります。",
                                    target_file=str(file.relative_to(repo_path)),
                                    line_number=i,
                                    evidence=line.strip()
                                ))
                            
                            # K8s特権コンテナチェック
                            if "privileged: true" in line.replace(" ", ""):
                                risks.append(RiskRecord(
                                    category=self.category,
                                    name="IaCにおける特権コンテナの許可",
                                    severity=Severity.CRITICAL,
                                    description="Kubernetesマニフェスト等で特権コンテナ(privileged: true)の実行が許可されています。",
                                    target_file=str(file.relative_to(repo_path)),
                                    line_number=i,
                                    evidence=line.strip()
                                ))

            except Exception:
                pass
                
        return risks
