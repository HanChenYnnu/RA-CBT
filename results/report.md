# Experiment Report

| baseline | scenario | attack_success_rate | false_reject_rate | throttle_rate |
|---|---:|---:|---:|---:|
| B0_static | S1_key_leak | 1.000 | 0.000 | 0.000 |
| B0_static | S2_token_leak | 1.000 | 0.000 | 0.000 |
| B0_static | S3_replay | 1.000 | 0.000 | 0.000 |
| B0_static | S4_burst | 1.000 | 0.000 | 0.000 |
| B0_static | S5_slowdrip | 1.000 | 0.000 | 0.000 |
| B0_static | S6_drift | 1.000 | 0.000 | 0.000 |
| B1_ip_allow | S1_key_leak | 1.000 | 0.000 | 0.000 |
| B1_ip_allow | S2_token_leak | 1.000 | 0.000 | 0.000 |
| B1_ip_allow | S3_replay | 1.000 | 0.000 | 0.000 |
| B1_ip_allow | S4_burst | 1.000 | 0.000 | 0.000 |
| B1_ip_allow | S5_slowdrip | 1.000 | 0.000 | 0.000 |
| B1_ip_allow | S6_drift | 1.000 | 0.000 | 0.000 |
| B2_bearer_short | S1_key_leak | 1.000 | 0.000 | 0.000 |
| B2_bearer_short | S2_token_leak | 1.000 | 0.000 | 0.000 |
| B2_bearer_short | S3_replay | 1.000 | 0.000 | 0.733 |
| B2_bearer_short | S4_burst | 1.000 | 0.000 | 0.000 |
| B2_bearer_short | S5_slowdrip | 1.000 | 0.000 | 0.000 |
| B2_bearer_short | S6_drift | 1.000 | 0.000 | 0.000 |
| B3_pop_only | S1_key_leak | 1.000 | 0.000 | 0.733 |
| B3_pop_only | S2_token_leak | 1.000 | 0.000 | 0.500 |
| B3_pop_only | S3_replay | 0.455 | 0.000 | 0.333 |
| B3_pop_only | S4_burst | 1.000 | 0.000 | 0.733 |
| B3_pop_only | S5_slowdrip | 1.000 | 0.000 | 0.000 |
| B3_pop_only | S6_drift | 1.000 | 0.000 | 0.000 |
| B4_full | S1_key_leak | 1.000 | 0.000 | 0.733 |
| B4_full | S2_token_leak | 1.000 | 0.000 | 0.733 |
| B4_full | S3_replay | 0.000 | 0.000 | 0.000 |
| B4_full | S4_burst | 1.000 | 0.000 | 0.733 |
| B4_full | S5_slowdrip | 1.000 | 0.000 | 0.367 |
| B4_full | S6_drift | 1.000 | 0.000 | 0.733 |
