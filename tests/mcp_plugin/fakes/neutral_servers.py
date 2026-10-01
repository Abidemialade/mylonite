"""Tool-surface fakes for the two official MCP reference servers used by the
issue #217 regression fixtures (``tests/fixtures/issue217/``).

"Neutral" because neither server is Mylonite's own reference target: these are
the same third-party, non-self-seeded servers the external-differential
campaign used (``verification/EXTERNAL_DIFFERENTIAL.md``'s "second proof"
table) — real app-design surfaces Mylonite did not author, so a false clean
against them is a real bug, not a self-fulfilling test.

Tool names, input schemas and MCP ``ToolAnnotations`` below are transcribed
BY HAND from the published packages' own ``dist/index.js`` (read, never
executed — the test suite never runs ``npx``/``uvx``):

    @modelcontextprotocol/server-memory       2026.8.31 (McpServer version "0.6.3")
    @modelcontextprotocol/server-filesystem   2026.8.31 (McpServer version "0.2.0")

Each zod ``inputSchema`` there is translated to the equivalent JSON Schema
shape (``type``/``properties``/``required``/``items``) — the same shape the
MCP TypeScript SDK sends over the wire in a real ``tools/list`` response and
``mylonite.scan.llm_types.ToolDescription.input_schema`` carries verbatim.
Exact ``$schema``/``additionalProperties`` framing the SDK may add is not
reproduced; only the properties, types and required-ness that any classifier
or JSON-Schema validator in this codebase actually looks at.

These are STRUCTURE fakes (``ToolSpec`` objects), not behavioural fakes: no
server process, no state store, no ``call_tool`` semantics. That is enough
for what consumes ``tools`` lists without a live session —
``_classify_tools``, ``consequential_tool_names``,
``scaffold._render_target_scaffold`` and ``calibration.validate_args`` all
operate purely on name + ``json_schema`` + ``annotations``. A session-level
fake (spawnable over ``mcp.ClientSession``, e.g. for a future
``tests/integration/test_issue217.py`` that drives a full scan) is NOT
provided here — out of scope for the #217 test-input task this module was
written for.
"""

from __future__ import annotations

from mylonite.contracts import ToolSpec

# --- server-memory ----------------------------------------------------------
#
# The knowledge-graph store: a flat JSONL file of entities (name, entityType,
# observations[]) and relations (from, to, relationType). No tool takes an
# opaque record "id" — entities are addressed by their own ``name`` string, so
# there is no id-capture step the way a database-style store would need.

_ENTITY_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "description": "The name of the entity"},
        "entityType": {"type": "string", "description": "The type of the entity"},
        "observations": {
            "type": "array",
            "items": {"type": "string"},
            "description": "An array of observation contents associated with the entity",
        },
    },
    "required": ["name", "entityType", "observations"],
}

_RELATION_SCHEMA = {
    "type": "object",
    "properties": {
        "from": {
            "type": "string",
            "description": "The name of the entity where the relation starts",
        },
        "to": {"type": "string", "description": "The name of the entity where the relation ends"},
        "relationType": {"type": "string", "description": "The type of the relation"},
    },
    "required": ["from", "to", "relationType"],
}

#: readOnlyHint=false, destructiveHint=false, idempotentHint=false, openWorldHint=false
_MEMORY_WRITE_ANNOTATIONS = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": False,
}

#: readOnlyHint=false, destructiveHint=true, idempotentHint=true, openWorldHint=false
_MEMORY_DELETE_ANNOTATIONS = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": True,
    "openWorldHint": False,
}

#: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false
_MEMORY_READ_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}


def memory_tools() -> list[ToolSpec]:
    """The full ``server-memory`` tool surface, in the server's own registration order."""

    return [
        ToolSpec(
            name="create_entities",
            description="Create multiple new entities in the knowledge graph",
            json_schema={
                "type": "object",
                "properties": {
                    "entities": {"type": "array", "items": _ENTITY_SCHEMA},
                },
                "required": ["entities"],
            },
            annotations=dict(_MEMORY_WRITE_ANNOTATIONS),
        ),
        ToolSpec(
            name="create_relations",
            description=(
                "Create multiple new relations between entities in the knowledge graph. "
                "Relations should be in active voice"
            ),
            json_schema={
                "type": "object",
                "properties": {
                    "relations": {"type": "array", "items": _RELATION_SCHEMA},
                },
                "required": ["relations"],
            },
            annotations=dict(_MEMORY_WRITE_ANNOTATIONS),
        ),
        ToolSpec(
            name="add_observations",
            description="Add new observations to existing entities in the knowledge graph",
            json_schema={
                "type": "object",
                "properties": {
                    "observations": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "entityName": {
                                    "type": "string",
                                    "description": "The name of the entity to add the observations to",
                                },
                                "contents": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "An array of observation contents to add",
                                },
                            },
                            "required": ["entityName", "contents"],
                        },
                    },
                },
                "required": ["observations"],
            },
            annotations=dict(_MEMORY_WRITE_ANNOTATIONS),
        ),
        ToolSpec(
            name="delete_entities",
            description=(
                "Delete multiple entities and their associated relations from the knowledge graph"
            ),
            json_schema={
                "type": "object",
                "properties": {
                    "entityNames": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "An array of entity names to delete",
                    },
                },
                "required": ["entityNames"],
            },
            annotations=dict(_MEMORY_DELETE_ANNOTATIONS),
        ),
        ToolSpec(
            name="delete_observations",
            description="Delete specific observations from entities in the knowledge graph",
            json_schema={
                "type": "object",
                "properties": {
                    "deletions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "entityName": {
                                    "type": "string",
                                    "description": "The name of the entity containing the observations",
                                },
                                "observations": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "An array of observations to delete",
                                },
                            },
                            "required": ["entityName", "observations"],
                        },
                    },
                },
                "required": ["deletions"],
            },
            annotations=dict(_MEMORY_DELETE_ANNOTATIONS),
        ),
        ToolSpec(
            name="delete_relations",
            description="Delete multiple relations from the knowledge graph",
            json_schema={
                "type": "object",
                "properties": {
                    "relations": {
                        "type": "array",
                        "items": _RELATION_SCHEMA,
                        "description": "An array of relations to delete",
                    },
                },
                "required": ["relations"],
            },
            annotations=dict(_MEMORY_DELETE_ANNOTATIONS),
        ),
        ToolSpec(
            name="read_graph",
            description="Read the entire knowledge graph",
            json_schema={"type": "object", "properties": {}, "required": []},
            annotations=dict(_MEMORY_READ_ANNOTATIONS),
        ),
        ToolSpec(
            name="search_nodes",
            description="Search for nodes in the knowledge graph based on a query",
            json_schema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": (
                            "The search query to match against entity names, types, "
                            "and observation content"
                        ),
                    },
                },
                "required": ["query"],
            },
            annotations=dict(_MEMORY_READ_ANNOTATIONS),
        ),
        ToolSpec(
            name="open_nodes",
            description="Open specific nodes in the knowledge graph by their names",
            json_schema={
                "type": "object",
                "properties": {
                    "names": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "An array of entity names to retrieve",
                    },
                },
                "required": ["names"],
            },
            annotations=dict(_MEMORY_READ_ANNOTATIONS),
        ),
    ]


# --- server-filesystem -------------------------------------------------------
#
# A sandboxed filesystem, rooted at the directories given on the launch
# command line. Every path-taking tool is validated against that allowlist
# server-side; the schemas below carry only the argument SHAPE, not that
# runtime check.

#: readOnlyHint=true, openWorldHint=false (no destructiveHint/idempotentHint declared)
_FS_READ_ANNOTATIONS = {"readOnlyHint": True, "openWorldHint": False}

#: readOnlyHint=false, idempotentHint=true, destructiveHint=true, openWorldHint=false
_FS_WRITE_ANNOTATIONS = {
    "readOnlyHint": False,
    "idempotentHint": True,
    "destructiveHint": True,
    "openWorldHint": False,
}

#: readOnlyHint=false, idempotentHint=false, destructiveHint=true, openWorldHint=false
_FS_EDIT_ANNOTATIONS = {
    "readOnlyHint": False,
    "idempotentHint": False,
    "destructiveHint": True,
    "openWorldHint": False,
}

#: readOnlyHint=false, idempotentHint=true, destructiveHint=false, openWorldHint=false
_FS_CREATE_DIR_ANNOTATIONS = {
    "readOnlyHint": False,
    "idempotentHint": True,
    "destructiveHint": False,
    "openWorldHint": False,
}


def filesystem_tools() -> list[ToolSpec]:
    """The full ``server-filesystem`` tool surface, in the server's own registration order."""

    read_text_file_schema = {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "tail": {
                "type": "number",
                "description": "If provided, returns only the last N lines of the file",
            },
            "head": {
                "type": "number",
                "description": "If provided, returns only the first N lines of the file",
            },
        },
        "required": ["path"],
    }

    return [
        ToolSpec(
            name="read_file",
            description=(
                "Read the complete contents of a file as text. "
                "DEPRECATED: Use read_text_file instead."
            ),
            json_schema=read_text_file_schema,
            annotations=dict(_FS_READ_ANNOTATIONS),
        ),
        ToolSpec(
            name="read_text_file",
            description=(
                "Read the complete contents of a file from the file system as text. "
                "Handles various text encodings and provides detailed error messages "
                "if the file cannot be read. Use this tool when you need to examine "
                "the contents of a single file. Use the 'head' parameter to read only "
                "the first N lines of a file, or the 'tail' parameter to read only "
                "the last N lines of a file. Operates on the file as text regardless of "
                "extension. Only works within allowed directories."
            ),
            json_schema=read_text_file_schema,
            annotations=dict(_FS_READ_ANNOTATIONS),
        ),
        ToolSpec(
            name="read_media_file",
            description=(
                "Read a file and return it as a base64-encoded content block with its "
                "MIME type. Image and audio files are returned as image/audio content; "
                "any other file type is returned as an embedded resource. Only works "
                "within allowed directories."
            ),
            json_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            annotations=dict(_FS_READ_ANNOTATIONS),
        ),
        ToolSpec(
            name="read_multiple_files",
            description=(
                "Read the contents of multiple files simultaneously. This is more "
                "efficient than reading files one by one when you need to analyze or "
                "compare multiple files. Each file's content is returned with its path "
                "as a reference. Failed reads for individual files won't stop the entire "
                "operation. Only works within allowed directories."
            ),
            json_schema={
                "type": "object",
                "properties": {
                    "paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 1,
                        "description": (
                            "Array of file paths to read. Each path must be a string "
                            "pointing to a valid file within allowed directories."
                        ),
                    },
                },
                "required": ["paths"],
            },
            annotations=dict(_FS_READ_ANNOTATIONS),
        ),
        ToolSpec(
            name="write_file",
            description=(
                "Create a new file or completely overwrite an existing file with new "
                "content. Use with caution as it will overwrite existing files without "
                "warning. Handles text content with proper encoding. Only works within "
                "allowed directories."
            ),
            json_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
            annotations=dict(_FS_WRITE_ANNOTATIONS),
        ),
        ToolSpec(
            name="edit_file",
            description=(
                "Make line-based edits to a text file. Each edit replaces exact line "
                "sequences with new content. Returns a git-style diff showing the "
                "changes made. Only works within allowed directories."
            ),
            json_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "edits": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "oldText": {
                                    "type": "string",
                                    "description": "Text to search for - must match exactly",
                                },
                                "newText": {
                                    "type": "string",
                                    "description": "Text to replace with",
                                },
                            },
                            "required": ["oldText", "newText"],
                        },
                    },
                    "dryRun": {
                        "type": "boolean",
                        "default": False,
                        "description": "Preview changes using git-style diff format",
                    },
                },
                "required": ["path", "edits"],
            },
            annotations=dict(_FS_EDIT_ANNOTATIONS),
        ),
        ToolSpec(
            name="create_directory",
            description=(
                "Create a new directory or ensure a directory exists. Can create "
                "multiple nested directories in one operation. If the directory already "
                "exists, this operation will succeed silently. Perfect for setting up "
                "directory structures for projects or ensuring required paths exist. "
                "Only works within allowed directories."
            ),
            json_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            annotations=dict(_FS_CREATE_DIR_ANNOTATIONS),
        ),
        ToolSpec(
            name="list_directory",
            description=(
                "Get a detailed listing of all files and directories in a specified "
                "path. Results clearly distinguish between files and directories with "
                "[FILE] and [DIR] prefixes. This tool is essential for understanding "
                "directory structure and finding specific files within a directory. "
                "Only works within allowed directories."
            ),
            json_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            annotations=dict(_FS_READ_ANNOTATIONS),
        ),
        ToolSpec(
            name="list_directory_with_sizes",
            description=(
                "Get a detailed listing of all files and directories in a specified "
                "path, including sizes. Results clearly distinguish between files and "
                "directories with [FILE] and [DIR] prefixes. This tool is useful for "
                "understanding directory structure and finding specific files within a "
                "directory. Only works within allowed directories."
            ),
            json_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "sortBy": {
                        "type": "string",
                        "enum": ["name", "size"],
                        "default": "name",
                        "description": "Sort entries by name or size",
                    },
                },
                "required": ["path"],
            },
            annotations=dict(_FS_READ_ANNOTATIONS),
        ),
        ToolSpec(
            name="directory_tree",
            description=(
                "Get a recursive tree view of files and directories as a JSON "
                "structure. Each entry includes 'name', 'type' (file/directory), and "
                "'children' for directories. Files have no children array, while "
                "directories always have a children array (which may be empty). The "
                "output is formatted with 2-space indentation for readability. Only "
                "works within allowed directories."
            ),
            json_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "excludePatterns": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": [],
                    },
                },
                "required": ["path"],
            },
            annotations=dict(_FS_READ_ANNOTATIONS),
        ),
        ToolSpec(
            name="move_file",
            description=(
                "Move or rename files and directories. Can move files between "
                "directories and rename them in a single operation. If the destination "
                "exists, the operation will fail. Works across different directories "
                "and can be used for simple renaming within the same directory. Both "
                "source and destination must be within allowed directories."
            ),
            json_schema={
                "type": "object",
                "properties": {
                    "source": {"type": "string"},
                    "destination": {"type": "string"},
                },
                "required": ["source", "destination"],
            },
            annotations=dict(_FS_EDIT_ANNOTATIONS),
        ),
        ToolSpec(
            name="search_files",
            description=(
                "Recursively search for files and directories matching a pattern. The "
                "patterns should be glob-style patterns that match paths relative to "
                "the working directory. Use pattern like '*.ext' to match files in "
                "current directory, and '**/*.ext' to match files in all "
                "subdirectories. Returns full paths to all matching items. Great for "
                "finding files when you don't know their exact location. Only searches "
                "within allowed directories."
            ),
            json_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "pattern": {"type": "string"},
                    "excludePatterns": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": [],
                    },
                },
                "required": ["path", "pattern"],
            },
            annotations=dict(_FS_READ_ANNOTATIONS),
        ),
        ToolSpec(
            name="get_file_info",
            description=(
                "Retrieve detailed metadata about a file or directory. Returns "
                "comprehensive information including size, creation time, last "
                "modified time, permissions, and type. This tool is perfect for "
                "understanding file characteristics without reading the actual "
                "content. Only works within allowed directories."
            ),
            json_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            annotations=dict(_FS_READ_ANNOTATIONS),
        ),
        ToolSpec(
            name="list_allowed_directories",
            description=(
                "Returns the list of directories that this server is allowed to "
                "access. Subdirectories within these allowed directories are also "
                "accessible. Use this to understand which directories and their nested "
                "paths are available before trying to access files."
            ),
            json_schema={"type": "object", "properties": {}, "required": []},
            annotations=dict(_FS_READ_ANNOTATIONS),
        ),
    ]
