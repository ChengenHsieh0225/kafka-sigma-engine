# Python Asyncio for the Rule Engine

The Rule Engine is implemented in Python using asyncio rather than Go. The primary driver is developer familiarity with Python, which reduces implementation risk for a side project. The decision accepts that Python's GIL prevents true multi-core parallelism within a single process; horizontal scaling via multiple Kafka consumer-group members is the mitigation strategy. Go would offer lower per-event latency and native goroutine-based worker pools, but the complexity cost outweighs the benefit given the project's goals.
