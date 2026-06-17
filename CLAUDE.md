# USER STORY MAP 
The truth for the project should be based on the [user story map](USER_STORY_MAP.md) which defines the tech stack, activities, backbone tasks, and user stories for each release. The user story map is the source of truth for what we are building and why.

If the user story map is not up to date or does not reflect the current state of the project, it should be updated immediately. The user story map should be reviewed regularly to ensure it still aligns with our goals and priorities.

Specific User Stories will define the detailed requirements for each feature or functionality we are building. These user stories should be clear, concise, and actionable, providing enough information for developers to implement the feature without ambiguity.

# Development Process

1. All code should be developed in feature branches based on the user stories defined in the user story map.
2. Start with tests that define the expected behavior of the feature (Test-Driven Development).
3. Implement the feature to make the tests pass.
4. Ensure code is well-documented and follows the project's [coding standards and architectural guidelines](ARCHITECTURE.md).
5. Mark the user story as "In Progress" in the user story map when development starts, and update it to "Done" once the feature is implemented and tested.
6. Update acceptance criteria in the user story as needed based on any implementations, changes or discoveries during development.
7. Always run all tests, linting, and formatting checks before merging code to the main branch. Using this command: `.venv/bin/pytest tests/ -q && .venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/mypy --strict system_sentinel/ 2>&1`


