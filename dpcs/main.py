# main.py

import hca
import node
import edge
import cv
import audit
import time


if __name__ == "__main__":

    print("=" * 65)
    print("        DPCS : Dual-Path Commitment Signature Demo")
    print("=" * 65)

    # =====================================================
    # 1. Initialize Entities
    # =====================================================
    myhca = hca.HCA()
    mynode = node.Node("iot-node-42", myhca)
    myedge = edge.Edge()
    mycv = cv.CloudVerifier(myhca.A)
    myaa = audit.AuditAuthority()

    print("[✓] All entities initialized")

    # =====================================================
    # 2. HCA issues dual certificate
    # =====================================================
    cert = myhca.issue_dual_cert(
        "iot-node-42",
        mynode.pk_CL,
        mynode.pk_PQ,
        epoch=1
    )

    print("[✓] Hybrid certificate issued")

    # =====================================================
    # 3. Prepare Message
    # =====================================================
    msg = b"temperature=36.5"
    timestamp = int(time.time())

    # =====================================================
    # 4. Node Signs
    # =====================================================
    sig = mynode.sign(
        msg,
        timestamp,
        battery_level=0.90   # FULL_HYBRID
    )

    print(f"[✓] Node signed message")
    print(f"    Trust Mode : {sig['trust_flag']}")

    # =====================================================
    # 5. Edge Partial Verification
    # =====================================================
    edge_ok = myedge.verify_partial(
        sig,
        mynode.pk,
        msg,
        timestamp
    )

    print(f"[✓] Edge Verification : {'PASS' if edge_ok else 'FAIL'}")

    # =====================================================
    # 6. Cloud Full Verification
    # =====================================================
    valid, trust = mycv.verify(
        sigma=sig,
        pk=mynode.pk,
        msg=msg,
        timestamp=timestamp,
        R_epoch=cert["R_epoch"],
        pi_leaf=cert["pi_epoch"],
        node_id=mynode.id_i,
        session_key=mynode.session_key
    )

    print(f"[✓] Cloud Verification : {valid}")
    print(f"[✓] Trust Level        : {trust}")

    # =====================================================
    # 7. Audit Verification
    # =====================================================
    audit_ok = myaa.audit(
        cert["R_epoch"],
        [cert["pi_epoch"]],
        [cert["pi_epoch"]["leaf"]]
    )

    print(f"[✓] Audit Result       : {audit_ok}")

    print("=" * 65)
    print("        All Process Completed Successfully")
    print("=" * 65)