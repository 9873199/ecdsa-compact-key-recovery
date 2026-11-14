# Compact recoverable signature verification

Post-session AI-assisted review, separate from original model tests. Python3.14.3; exact dependency locks and source import paths retained. compact-oracle-r1: python -B -m pytest -q test_compact_signature_review.py =>41 pass, independent HMAC RFC6979 plus affine secp256k1 and cryptography cross-check; model added28 pass. compact-upstream-r2: python -B run_upstream_with_openssl.py -q src/ecdsa --ignore=src/ecdsa/test_compact_recovery.py -o addopts= =>2038 pass6 skip4 upstream warnings. Set PATH to a local OpenSSL installation; reviewed Windows Git OpenSSL3.5.5 used here. First all-suite collection failed for missing openssl.exe (2 errors); original logs retained, excluded from product scoring. Scopes overlap and are not summed. No service, container or external TSA/network needed. Test keys are offline/generated and no secret printed.

Use the matching frozen source commit; put its src and selected verification directory on PYTHONPATH. The75-second recording is openly automated; actual keystrokes, whole-word repair and program output retained. No source edits after freeze; no automatic submission.


冻结产物提交：https://github.com/9873199/ecdsa-compact-key-recovery/commit/d004987447b49cce40958aa6a8d2a2c1b74170e8
这些独立验收文件在模型首轮结束后生成，不是模型原轨中的测试。
