import asyncio
from mcp.client.sse import sse_client
from mcp import ClientSession

async def main():
    url = "http://127.0.0.1:8000/sse"
    async with sse_client(url) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # chiamata a cwe_knowledge per CWE-89
            result = await session.call_tool("cwe_knowledge", {"cwe": "CWE-89"})
            # estrai testo dai blocchi del result
            text = "\n".join(getattr(b, "text", "") or "" for b in result.content)
            print(text)

if __name__ == "__main__":
    asyncio.run(main())