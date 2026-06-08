```markdown
# quantgroup Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches the core development patterns and conventions used in the `quantgroup` TypeScript codebase. It covers file naming, import/export styles, test patterns, and provides step-by-step workflows for common tasks. By following these guidelines, you can contribute code that is consistent with the existing repository style.

## Coding Conventions

### File Naming
- Use **PascalCase** for all file names.
  - Example: `MyModule.ts`, `UserService.ts`

### Import Style
- Use **relative imports** for referencing other modules within the project.
  - Example:
    ```typescript
    import { SomeUtil } from './SomeUtil';
    ```

### Export Style
- Use **named exports** for all modules.
  - Example:
    ```typescript
    // In MyModule.ts
    export function myFunction() { ... }
    export const MY_CONST = 42;

    // In another file
    import { myFunction, MY_CONST } from './MyModule';
    ```

### Commit Message Patterns
- Commit messages are **freeform**, with no enforced prefix.
- Average commit message length is about 62 characters.

## Workflows

### Adding a New Module
**Trigger:** When you need to add a new feature or utility.
**Command:** `/add-module`

1. Create a new file using PascalCase, e.g., `NewFeature.ts`.
2. Implement your logic using named exports.
3. Use relative imports to include dependencies.
4. Write corresponding tests in a file named `NewFeature.test.ts`.
5. Commit your changes with a clear, descriptive message.

### Updating an Existing Module
**Trigger:** When modifying or extending existing functionality.
**Command:** `/update-module`

1. Locate the module file (e.g., `ExistingFeature.ts`).
2. Make your changes using named exports.
3. Update or add tests in the corresponding `*.test.ts` file.
4. Commit your changes with a descriptive message.

### Writing Tests
**Trigger:** When adding or updating functionality.
**Command:** `/write-test`

1. Create or update a test file named `ModuleName.test.ts`.
2. Implement test cases for each exported function or constant.
3. Use the project's preferred (unknown) testing framework.
4. Run tests to ensure correctness.

## Testing Patterns

- Test files are named with the pattern `*.test.ts`, matching the module they test.
  - Example: `MyModule.test.ts` tests `MyModule.ts`.
- The specific testing framework is not detected; follow existing patterns in the repository.
- Place test files alongside or near their corresponding modules.

## Commands
| Command         | Purpose                                      |
|-----------------|----------------------------------------------|
| /add-module     | Start workflow for adding a new module       |
| /update-module  | Start workflow for updating a module         |
| /write-test     | Start workflow for writing or updating tests |
```
