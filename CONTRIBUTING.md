# 贡献指南

```bash
pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

- 提交前确保 `python -m unittest` 全绿。
- 涉及协议/令牌格式的改动请同时在 `CHANGELOG.md` 记录，并说明兼容性影响。
- 不要提交任何 `.pem` / `.db` / `config.json` / 测试卡号。
- 新增接口请补一条端到端用例（`tests/test_licensekit.py::TestServerEndToEnd`）。