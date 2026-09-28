"""The single shared FastMCP instance.

Every tool module and the registry import `mcp` from here and attach their tools
to it, so there is exactly one server object assembled across the package.
"""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("codeql")
