"""Register (or update) the leak incident flow in the GitLab AI Catalog and
wire it to fire when a pipeline in this project fails.

Run locally with a personal access token that has the `api` scope:

    python ci/register_flow.py --token-header-file ~/.secrets/gitlab.header \
        --project-path group/sub/vibeguardian

The token header file holds one line: "PRIVATE-TOKEN: <token>".
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import requests

GRAPHQL = "https://gitlab.com/api/graphql"


class GraphQL:
    def __init__(self, header_file: str):
        name, value = Path(header_file).read_text(encoding="utf-8").strip().split(":", 1)
        self.headers = {name.strip(): value.strip(), "Content-Type": "application/json"}

    def __call__(self, query: str, variables: dict | None = None) -> dict:
        response = requests.post(GRAPHQL, headers=self.headers, json={"query": query, "variables": variables or {}},
                                 timeout=60)
        body = response.json()
        if body.get("errors"):
            raise SystemExit(f"GraphQL error: {json.dumps(body['errors'])[:800]}")
        return body["data"]


def find_flow(gql: GraphQL, project_path: str, name: str) -> dict | None:
    data = gql("query($path: ID!) { project(fullPath: $path) { id } }", {"path": project_path})
    project_gid = data["project"]["id"]
    found = gql(
        """query($search: String) { aiCatalogItems(search: $search, itemTypes: [FLOW]) {
             nodes { id name project { id } } } }""",
        {"search": name},
    )["aiCatalogItems"]["nodes"]
    for item in found:
        if item["name"] == name and (item.get("project") or {}).get("id") == project_gid:
            return {"item": item, "project_gid": project_gid}
    return {"item": None, "project_gid": project_gid}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--token-header-file", required=True)
    parser.add_argument("--project-path", required=True)
    parser.add_argument("--flow-file", default="flows/leak-incident.yml")
    parser.add_argument("--name", default="VibeGuardian leak incident")
    parser.add_argument("--description", default=(
        "When a pipeline fails because VibeGuardian retired a leaked Google API key, writes the incident "
        "up from fingerprint-only evidence and opens the merge request that removes the key from the code."
    ))
    parser.add_argument("--enable", action="store_true",
                        help="also turn the flow on here, triggered by failed pipelines (first run only)")
    args = parser.parse_args()

    gql = GraphQL(args.token_header_file)
    definition = Path(args.flow_file).read_text(encoding="utf-8")
    state = find_flow(gql, args.project_path, args.name)
    project_gid = state["project_gid"]

    if state["item"]:
        item_id = state["item"]["id"]
        data = gql(
            """mutation($input: AiCatalogFlowUpdateInput!) { aiCatalogFlowUpdate(input: $input) {
                 errors item { id latestVersion { id } } } }""",
            {"input": {"id": item_id, "definition": definition, "release": True}},
        )["aiCatalogFlowUpdate"]
        print("updated flow", item_id, data["errors"] or "")
    else:
        data = gql(
            """mutation($input: AiCatalogFlowCreateInput!) { aiCatalogFlowCreate(input: $input) {
                 errors item { id name } } }""",
            {"input": {"projectId": project_gid, "name": args.name, "description": args.description,
                       "visibility": "PRIVATE", "release": True, "definition": definition}},
        )["aiCatalogFlowCreate"]
        if data["errors"]:
            sys.exit(f"create failed: {data['errors']}")
        item_id = data["item"]["id"]
        print("created flow", item_id)

    if args.enable:
        # Turn the flow on in this project. GitLab creates the flow's service
        # account and a trigger that fires when a pipeline here fails.
        data = gql(
            """mutation($input: AiCatalogItemConsumerCreateInput!) { aiCatalogItemConsumerCreate(input: $input) {
                 errors itemConsumer { id flowTriggers { id eventTypes filter user { username } } } } }""",
            {"input": {
                "itemId": item_id,
                "target": {"projectId": project_gid},
                "triggerTypes": ["pipeline_hooks"],
                "triggerConditions": {"pipelineHooks": {"match": "ALL", "rules": [
                    {"field": "object_attributes.status", "operator": "EQ", "value": "failed"}]}},
            }},
        )["aiCatalogItemConsumerCreate"]
        if data["errors"]:
            sys.exit(f"enable failed: {data['errors']}")
        print("enabled:", json.dumps(data["itemConsumer"]))

    print(json.dumps({"item_id": item_id, "project_gid": project_gid}))


if __name__ == "__main__":
    main()
