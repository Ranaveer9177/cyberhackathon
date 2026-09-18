# VibeGuard — Architecture

## 1. Architecture Overview

VibeGuard follows a modular security-scanning architecture.

```text
                    VibeGuard CLI
                         |
                         v
                  Core Application
                         |
              +----------+----------+
              |                     |
              v                     v
        Security Scanner       Dependency Engine
              |                     |
      +-------+-------+             v
      |       |       |            OSV
      v       v       v
   Secrets  SAST   Files
      |       |       |
      +-------+-------+
              |
              v
        Finding Engine
              |
              v
         Risk Engine
              |
       +------+------+
       |      |      |
       v      v      v
   Terminal  JSON   HTML
              |
              v
        PASS / BLOCK