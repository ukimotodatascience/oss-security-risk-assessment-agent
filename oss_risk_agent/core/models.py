from enum import Enum
from typing import List, Optional
from pydantic import BaseModel
from abc import ABC, abstractmethod
from pathlib import Path


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskRecord(BaseModel):
    category: str  # e.g., "A-1", "B-2"
    name: str  # e.g., "既知の脆弱性を含む依存ライブラリ"
    severity: Severity  # 評価された重大度
    description: str  # リスクの詳細な説明
    target_file: str  # 検出されたファイル名など（証拠）
    line_number: Optional[int] = None  # 該当行番号（可能な場合）
    evidence: str  # なぜ検出したかの具体的な根拠・スニペット
    score_metadata: Optional[dict] = (
        None  # JSON metadata for exact scores like CVSS/EPSS
    )


class ScanWarning(BaseModel):
    rule_category: str
    rule_name: str
    message: str


class Rule(ABC):
    """
    OSSリスク診断の基本ルールインターフェース
    """

    @property
    @abstractmethod
    def category(self) -> str:
        """ルールのカテゴリ (例: 'A-1')"""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """ルール名"""
        pass

    @abstractmethod
    def analyze(self, repo_path: Path) -> List[RiskRecord]:
        """リポジトリを解析し、検出したリスクのリストを返す"""
        pass
