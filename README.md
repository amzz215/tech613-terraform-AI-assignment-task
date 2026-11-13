# Terraform Pre-Deployment Checker

Open Git Bash in this folder and run:

```bash
python -m venv .venv
source .venv/Scripts/activate
python check_terraform.py main.tf
```

The checker uses Python's standard library and checks the local Terraform file. The baseline run should report zero failed checks and two warnings.