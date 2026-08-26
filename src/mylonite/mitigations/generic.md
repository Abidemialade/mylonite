This finding is a weakness in your agent's AI layer. Review the system prompt,
the tool/function schemas, and how untrusted content (tool results, retrieved
documents, message history) reaches the model. Treat all such content as data,
never as instructions; constrain which tools the model may call and require
human confirmation for consequential actions.
