from pathlib import Path
import sys


OLD = """        finally:
            try:
                if mcp_clients := metadata.get("mcp_clients"):
                    for client in reversed(mcp_clients.values()):
                        await client.disconnect()
            except Exception as e:
                log.debug(f"Error cleaning up: {e}")
                pass
            # Emit chat:active=false when task completes
"""


NEW = """        finally:
            try:
                if mcp_clients := metadata.get("mcp_clients"):
                    for client in reversed(mcp_clients.values()):
                        if client is None:
                            continue
                        try:
                            await asyncio.shield(client.disconnect())
                        except Exception as e:
                            log.warning(f"Error cleaning up MCP client: {e}")
            except Exception as e:
                log.debug(f"Error cleaning up: {e}")
                pass
            # Emit chat:active=false when task completes
"""


def main():
    path = Path(sys.argv[1])
    text = path.read_text()

    if OLD not in text:
        raise RuntimeError("Expected cleanup block not found in main.py")

    path.write_text(text.replace(OLD, NEW, 1))


if __name__ == "__main__":
    main()
