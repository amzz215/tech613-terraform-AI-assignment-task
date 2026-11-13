#!/usr/bin/env python3
"""Static checks for the two-tier EC2 Terraform configuration in main.tf.

Requires Python 3.9+ and only the standard library. Does not access AWS.
Run: python check_terraform.py main.tf
"""

import argparse
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Block:
    kind: str
    type: str
    name: str
    body: str
    line: int


HEADERS = (
    ("resource", re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')),
    ("data", re.compile(r'^\s*data\s+"([^"]+)"\s+"([^"]+)"\s*\{')),
    ("variable", re.compile(r'^\s*variable\s+"([^"]+)"\s*\{')),
    ("module", re.compile(r'^\s*module\s+"([^"]+)"\s*\{')),
)


def brace_change(line, state):
    """Count HCL braces outside strings/comments/heredocs for this file's syntax."""
    if state["heredoc"]:
        if line.strip() == state["heredoc"]:
            state["heredoc"] = None
        return 0

    difference = 0
    i = 0
    quoted = False
    while i < len(line):
        if state["comment"]:
            close = line.find("*/", i)
            if close < 0:
                return difference
            state["comment"] = False
            i = close + 2
            continue

        c = line[i]
        if quoted:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                quoted = False
            i += 1
            continue

        if line.startswith("/*", i):
            state["comment"] = True
            i += 2
            continue
        if c == "#" or line.startswith("//", i):
            break
        if c == '"':
            quoted = True
            i += 1
            continue
        if line.startswith("<<", i):
            marker = re.match(r'<<-?([A-Za-z_][A-Za-z0-9_]*)', line[i:])
            if marker:
                state["heredoc"] = marker.group(1)
                i += len(marker.group(0))
                continue
        if c == "{":
            difference += 1
        elif c == "}":
            difference -= 1
        i += 1
    return difference


def extract_blocks(source):
    blocks = []
    depth = 0
    active = None
    lines = []
    state = {"heredoc": None, "comment": False}

    for line_no, line in enumerate(source.splitlines(), 1):
        if depth == 0 and not state["heredoc"] and not state["comment"]:
            for kind, pattern in HEADERS:
                match = pattern.match(line)
                if match:
                    if kind in ("resource", "data"):
                        typ, name = match.groups()
                    else:
                        typ, name = "", match.group(1)
                    active = (kind, typ, name, line_no)
                    lines = []
                    break

        if active is not None:
            lines.append(line)
        depth += brace_change(line, state)
        if depth < 0:
            raise ValueError(f"Unbalanced closing brace at line {line_no}")

        if active is not None and depth == 0:
            kind, typ, name, start_line = active
            blocks.append(Block(kind, typ, name, "\n".join(lines), start_line))
            active = None
            lines = []

    if depth or active is not None or state["heredoc"] or state["comment"]:
        raise ValueError("Unterminated HCL block, comment, or heredoc")
    return blocks


def attribute(block, name):
    if block is None:
        return None
    matches = re.findall(rf'^\s*{re.escape(name)}\s*=\s*(.*?)\s*$', block.body, re.M)
    if len(matches) > 1:
        raise ValueError(f"Duplicate '{name}' in {block.kind} {block.name}")
    return matches[0] if matches else None


def quoted_value(expression):
    if expression and expression.startswith('"') and expression.endswith('"'):
        try:
            return json.loads(expression)
        except json.JSONDecodeError:
            return None
    return None


class Checker:
    def __init__(self, blocks):
        self.blocks = blocks
        self.failures = 0
        self.warnings = 0
        self.defaults = {}
        for block in blocks:
            if block.kind == "variable":
                self.defaults[block.name] = attribute(block, "default")

    def report(self, ok, label, details=""):
        print(f"[{'PASS' if ok else 'FAIL'}] {label}" + (f" — {details}" if details else ""))
        if not ok:
            self.failures += 1

    def warning(self, label):
        print(f"[WARN] {label}")
        self.warnings += 1

    def block(self, kind, typ, name):
        found = [b for b in self.blocks if (b.kind, b.type, b.name) == (kind, typ, name)]
        if len(found) != 1:
            self.report(False, f"Exactly one {kind} {typ or ''} {name} exists", f"found {len(found)}")
            return None
        return found[0]

    def resolve(self, expression):
        """Resolve literal values and simple var.X defaults, not arbitrary HCL."""
        if expression is None:
            return None
        expression = expression.strip()
        if expression.startswith("var.") and re.fullmatch(r'var\.[A-Za-z_][A-Za-z0-9_]*', expression):
            return self.resolve(self.defaults.get(expression[4:]))
        if expression in ("true", "false"):
            return expression == "true"
        if re.fullmatch(r'-?\d+', expression):
            return int(expression)
        return quoted_value(expression)

    def value(self, block, name, expected, label):
        actual = self.resolve(attribute(block, name))
        self.report(actual == expected, label, f"expected {expected!r}; got {actual!r}")

    def expression(self, block, name, expected, label):
        actual = attribute(block, name)
        self.report(actual == expected, label, f"expected {expected}; got {actual or 'MISSING'}")

    def check_rule(self, typ, name, sg, port, source_key, source_expr):
        r = self.block("resource", typ, name)
        if r is None:
            return
        description = name.replace("_", " ")
        self.expression(r, "security_group_id", sg, f"{description}: correct security group")
        self.value(r, "from_port", port, f"{description}: from_port {port}")
        self.value(r, "to_port", port, f"{description}: to_port {port}")
        self.value(r, "ip_protocol", "tcp", f"{description}: TCP protocol")
        sources = ("cidr_ipv4", "cidr_ipv6", "prefix_list_id", "referenced_security_group_id")
        actual_sources = {key: attribute(r, key) for key in sources if attribute(r, key) is not None}
        self.report(
            actual_sources == {source_key: source_expr},
            f"{description}: correct and only source/destination",
            f"got {actual_sources}",
        )

    def run(self):
        app_sg = "aws_security_group.allow_ports.id"
        db_sg = "aws_security_group.allow_db_ports.id"
        app = self.block("resource", "aws_instance", "my_first_tf_instance")
        db = self.block("resource", "aws_instance", "my_first_tf_instance_db")
        sg_app = self.block("resource", "aws_security_group", "allow_ports")
        sg_db = self.block("resource", "aws_security_group", "allow_db_ports")
        subnet_db = self.block("resource", "aws_subnet", "db_private_subnet")
        vpc = self.block("module", "", "vpc")

        print("\nEC2 instances")
        instance_names = [b.name for b in self.blocks if b.kind == "resource" and b.type == "aws_instance"]
        self.report(sorted(instance_names) == ["my_first_tf_instance", "my_first_tf_instance_db"],
                    "Only the expected two EC2 instances are declared", f"found {instance_names}")
        for instance, label, security_group, subnet, public_ip in (
            (app, "App", app_sg, "module.vpc.public_subnets[0]", True),
            (db, "DB", db_sg, "aws_subnet.db_private_subnet.id", False),
        ):
            if instance is None:
                continue
            self.value(instance, "instance_type", "t3.micro", f"{label}: EC2 type is t3.micro")
            self.expression(instance, "vpc_security_group_ids", f"[{security_group}]", f"{label}: only intended security group attached")
            self.expression(instance, "subnet_id", subnet, f"{label}: correct subnet")
            self.value(instance, "associate_public_ip_address", public_ip, f"{label}: public IP assignment")
            ami = self.resolve(attribute(instance, "ami"))
            self.report(bool(ami and re.fullmatch(r'ami-[0-9a-f]+', ami)), f"{label}: AMI ID provided", f"got {ami!r}")

        if app and db:
            key_app = self.resolve(attribute(app, "key_name"))
            key_db = self.resolve(attribute(db, "key_name"))
            self.report(bool(key_app and key_db and key_app == key_db),
                        "Both instances have the same declared SSH key", f"app={key_app!r}, db={key_db!r}")
            expected = 'replace(var.app_user_data, "DB-PRIVATE-IP", aws_instance.my_first_tf_instance_db.private_ip)'
            self.expression(app, "user_data", expected, "App injects DB private IP into user_data")

        print("\nNetwork and security groups")
        for sg, label in ((sg_app, "App"), (sg_db, "DB")):
            if sg is not None:
                self.expression(sg, "vpc_id", "module.vpc.vpc_id", f"{label}: SG belongs to the app VPC")
                inline = re.search(r'^\s*(ingress|egress)\s*\{', sg.body, re.M)
                self.report(not inline, f"{label}: no unchecked inline SG rules")

        self.check_rule("aws_vpc_security_group_ingress_rule", "allow_ssh", app_sg, 22,
                        "cidr_ipv4", '"${trimspace(data.http.my_ip.response_body)}/32"')
        self.check_rule("aws_vpc_security_group_ingress_rule", "allow_http", app_sg, 80,
                        "cidr_ipv4", '"0.0.0.0/0"')
        self.check_rule("aws_vpc_security_group_ingress_rule", "allow_mongodb", db_sg, 27017,
                        "referenced_security_group_id", app_sg)
        self.check_rule("aws_vpc_security_group_egress_rule", "app_to_db_outbound_traffic", app_sg, 27017,
                        "referenced_security_group_id", db_sg)

        expected_ingress = {"allow_ssh", "allow_http", "allow_mongodb"}
        expected_egress = {"app_to_db_outbound_traffic"}
        ingress = {b.name for b in self.blocks if b.kind == "resource" and b.type == "aws_vpc_security_group_ingress_rule"}
        egress = {b.name for b in self.blocks if b.kind == "resource" and b.type == "aws_vpc_security_group_egress_rule"}
        self.report(ingress == expected_ingress,
                    "No additional standalone ingress rules (e.g. public 3000/27017)",
                    f"declared {sorted(ingress)}")
        self.report(egress == expected_egress, "No additional standalone egress rules",
                    f"declared {sorted(egress)}")
        if egress == expected_egress:
            self.warning("App SG only explicitly permits new outbound TCP 27017 to DB;"
                         " outbound web/package downloads may be blocked")
        old_rules = [b.name for b in self.blocks if b.kind == "resource" and b.type == "aws_security_group_rule"]
        self.report(not old_rules, "No legacy aws_security_group_rule resources bypass these checks",
                    f"found {old_rules}" if old_rules else "")

        ip_data = self.block("data", "http", "my_ip")
        self.value(ip_data, "url", "https://checkip.amazonaws.com", "SSH IP comes from the expected lookup URL") if ip_data else None

        print("\nVPC, private subnet and app configuration")
        if subnet_db:
            self.expression(subnet_db, "vpc_id", "module.vpc.vpc_id", "DB: subnet belongs to the app VPC")
            self.value(subnet_db, "map_public_ip_on_launch", False, "DB: subnet does not auto-assign public IPs")
            self.expression(subnet_db, "cidr_block", "var.private_subnet_cidrs[0]",
                            "DB: subnet CIDR is from the private-subnet variable")
            self.value(subnet_db, "availability_zone", "eu-west-1b", "DB: expected availability zone")
        if vpc:
            self.value(vpc, "source", "terraform-aws-modules/vpc/aws", "VPC module source matches")
            self.value(vpc, "enable_nat_gateway", False, "VPC: NAT gateway disabled as configured")
            self.value(vpc, "cidr", "10.0.0.0/16", "VPC: address range matches")
            self.expression(vpc, "public_subnets", "var.public_subnet_cidrs", "App public subnet CIDRs come from variable")
            self.expression(vpc, "private_subnets", "[]", "Private subnet is managed separately")
            try:
                public_cidrs = json.loads(self.defaults.get("public_subnet_cidrs", ""))
                private_cidrs = json.loads(self.defaults.get("private_subnet_cidrs", ""))
                vpc_net = ipaddress.ip_network(self.resolve(attribute(vpc, "cidr")))
                networks = [ipaddress.ip_network(value) for value in public_cidrs + private_cidrs]
                inside = bool(public_cidrs and private_cidrs) and all(net.subnet_of(vpc_net) for net in networks)
                distinct = all(not a.overlaps(b) for i, a in enumerate(networks)
                               for b in networks[i + 1:])
                self.report(inside, "Public/private CIDRs are valid and within VPC CIDR")
                self.report(distinct, "Public/private subnet CIDRs do not overlap")
            except (ValueError, TypeError, AttributeError):
                self.report(False, "Public/private subnet CIDRs must be valid literal defaults")
            if attribute(vpc, "version") is None:
                self.warning("VPC module version is not pinned; future module releases could change behavior")

        user_data = self.block("variable", "", "app_user_data")
        if user_data:
            self.report('mongodb://DB-PRIVATE-IP:27017/' in user_data.body,
                        "App user_data targets the DB on MongoDB port 27017")

        # Intentional isolation: the DB subnet inherits the VPC's main route table.
        # It must not be explicitly attached to the app's public route table.
        associated = [
            b for b in self.blocks
            if b.kind == "resource" and b.type == "aws_route_table_association"
            and attribute(b, "subnet_id") == "aws_subnet.db_private_subnet.id"
        ]
        self.report(
            not associated,
            "DB: no explicit route-table association (inherits VPC main route table)",
            f"found {[b.name for b in associated]}" if associated else "",
        )
        # This project does not intentionally modify the main route table.
        # Catch additions that require a closer review of isolation.
        routing_changes = [
            f"{b.type}.{b.name}"
            for b in self.blocks
            if b.kind == "resource" and b.type in {
                "aws_main_route_table_association", "aws_default_route_table", "aws_route"
            }
        ]
        self.report(
            not routing_changes,
            "No additional Terraform routing changes that could undermine DB isolation",
            f"found {routing_changes}" if routing_changes else "",
        )

        print(f"\nSUMMARY: {self.failures} failed, {self.warnings} warning(s)")
        if self.failures:
            print("RESULT: FAIL — Terraform configuration does not match the expected checks")
        else:
            print("RESULT: PASS — declared configuration matches these static checks")
        print("NOTE: DB subnet inherits the main route table; isolation depends on that table having no internet route.")
        print("NOTE: Static check only; overrides, other .tf files, deployed AWS routes/state are not verified.")
        return 1 if self.failures else 0


def main():
    parser = argparse.ArgumentParser(description="Check the two-tier Terraform EC2 and security-group configuration")
    parser.add_argument("file", nargs="?", default="main.tf", help="Terraform file to check (default: main.tf)")
    args = parser.parse_args()
    path = Path(args.file)
    try:
        content = path.read_text(encoding="utf-8")
        blocks = extract_blocks(content)
        print(f"Checking {path} ({len(blocks)} HCL blocks detected)")
        return Checker(blocks).run()
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
