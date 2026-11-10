# Managing ordered firewall rules

Open Firewall with an authorized account. The table shows the selected Local
Draft, Candidate, Running or Startup configuration. Search and action filters
restrict the displayed rows without changing the policy.

1. Select Local Draft and Add rule, or select a rule ID to edit it. Fill the
   source, destination, protocol, port ranges and Allow/Deny action. Where the
   runtime supports schema 4, clear Enabled to keep the rule without evaluating
   traffic. Keep in local draft does not change the server or kernel.
2. Drag the six-dot handle to reorder. Alternatively, focus the handle, press
   Space, use arrows or Home/End, then Enter; Escape cancels. The row action menu
   offers Move to position. Clear filters and close the editor before reordering.
3. Review changes, Stage candidate, then Validate candidate. Commit now applies
   the candidate. Commit with confirmation adds a deadline; verify connectivity
   before confirming the running revision. An unconfirmed commit reverts according
   to the server transaction contract.
4. Review Execution and At next boot. These compare each displayed rule and its
   position. The revision status indicates whether the whole Running revision is
   saved. Save running to startup stores all rules and their order for boot.
5. Use revision history to restore an authorized historical revision. Review the
   effective state after any failure before attempting another operation.

An unsaved Running revision can survive a service restart because it is journaled.
It differs from Startup used at appliance boot. A disabled rule can be committed
and saved; it remains visible but has no packet counters. A local disabled change
is not effective until committed. Unknown counters never mean zero traffic.

Light is the default; Dark is an explicit preference. No host firewall, forwarding,
NAT or management interface is changed by these browser controls outside the
authorized isolated deployment. Follow the deployment's native verification
procedure before treating traffic enforcement or recovery as validated.
