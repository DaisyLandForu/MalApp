from __future__ import annotations

import unittest
from io import BytesIO

from openpyxl import Workbook

from engine.excel_import import excel_preview


class ExcelImportTest(unittest.TestCase):
    def test_preview_reads_sheet_headers_and_rows(self) -> None:
        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "样本数据"
        sheet.append(["MD5", "应用名称", "风险分数"])
        sheet.append(["A" * 32, "测试应用一", 80])
        sheet.append(["B" * 32, "测试应用二", 20])
        content = BytesIO()
        workbook.save(content)

        preview = excel_preview(content.getvalue())

        self.assertEqual("样本数据", preview["selected_sheet"])
        self.assertEqual(2, preview["total_rows"])
        self.assertEqual(["MD5", "应用名称", "风险分数"], preview["headers"])
        self.assertEqual("测试应用一", preview["preview_rows"][0][1])


if __name__ == "__main__":
    unittest.main()
