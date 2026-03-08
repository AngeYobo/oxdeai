# Diagrams

OxDeAI diagrams are maintained with Excalidraw to keep architecture visuals editable, reviewable, and version-controlled.

## Policy

- Create and edit diagrams in https://excalidraw.com
- Store editable source in `.excalidraw` files
- Export rendered files as `.svg`
- Use `.svg` files in `README.md` and protocol/docs pages
- When updating a diagram, commit both the `.excalidraw` source and the `.svg` export

Example:

- `agent-authorization-boundary.excalidraw` -> editable source
- `agent-authorization-boundary.svg` -> rendered documentation image

## Editing Workflow

1. Open https://excalidraw.com
2. Load the target `.excalidraw` file from `docs/diagrams/`
3. Edit the diagram
4. Export `.svg` with scene data embedded
5. Commit both `.excalidraw` and `.svg`

## File Set

- `agent-authorization-boundary.*`
- `pdp-pep-flow.*`
- `verification-envelope-flow.*`
- `adapter-sidecar-architecture.*`
