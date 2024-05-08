from dataclasses import dataclass
from abc import ABC


@dataclass
class WrapperRequest:
    data: str | dict
    character: int
    main_url: str
    headers: dict
    condition: ABC


@dataclass
class DB:
    name: str
    tables: list


@dataclass
class Table:
    name: str
    columns: list
    rows: list

    def concat_columns(self) -> str:
        return ",'|',".join(f"{self.name}.{column}" for column in self.columns)
