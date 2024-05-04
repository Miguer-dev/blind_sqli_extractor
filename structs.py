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
        """Concatenates the columns to display them"""

        return ",'|',".join(self.columns)
