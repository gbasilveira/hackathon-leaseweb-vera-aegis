# Demonstration boundaries

The control-plane adapter operates synthetic workloads persisted as SQLite JSON collections. The local operator can reset the demonstration, select a simulated approver and change configured dependencies. A single incident is active per database. Export existing evidence before resetting. Polling and the small in-memory graph are intended for a hackathon-sized inventory.

Policy and context are local authoritative inputs. Whoever can alter the database, application or scenario files can subvert the demonstration. The evidence manifest describes observed local state and decision history. It has no external signature or time anchor.

The design uses application-level tool isolation and a fixed simulator API. Third-party MCP servers and the vendor SDK are trusted executable software. Review the external server implementation and runtime permissions before enabling it. The deployment has no live hypervisor adapter or provider-specific token revocation semantics.
