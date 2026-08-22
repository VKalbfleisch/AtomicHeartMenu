# Contributing to Atomic Heart Menu

Thanks for your interest. This is a beta, solo, amateur project. The bar is "make
it better without breaking the crash-safety model", not "perfect code". These
rules keep the codebase consistent and keep pull requests and issues easy to
review.

## Ground rules

- **Single-player only.** Do not add anything that targets multiplayer or online
  play. Atomic Heart has no multiplayer, and this project will never support
  cheating against other players.
- **License.** This project is licensed under GPL-3.0-or-later with the
  attribution terms in [`NOTICE`](NOTICE). By contributing you agree that:
  - your contribution is licensed under the same GPL-3.0-or-later terms,
  - you have the right to submit it, and
  - attribution to the author and to the third-party tools (Dumper-7, MinHook,
    Dear ImGui) stays intact.

## Before you start

- Search existing issues first. For anything non-trivial, open an issue to discuss
  the approach before you send a pull request.
- Keep changes focused: one logical change per pull request.

## Building

Confirm your change compiles in Release before opening a pull request:

```bat
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Outputs land in `bin\`. The dumped game SDK is not required to build.

## Code style

- Match the surrounding code. When in doubt, copy the style of the file you edit.
- C++17. Four-space indentation, no tabs. Allman braces (the opening brace goes on
  its own line), as in the existing code.
- Descriptive names. Avoid abbreviations that the codebase does not already use.
- Keep the SPDX and copyright header at the top of every new source file. Copy it
  from an existing file.

## Crash-safety rules (non-negotiable)

This DLL must never crash the game. Follow the existing safety model:

- Guard **every** game-memory dereference with `Mem::IsReadable` before you read or
  write it.
- Guard every **indirect call** into game code with `Mem::IsExecutable`, never with
  `Mem::IsReadable`. Readable is not executable, and a bad function pointer that
  reads fine still DEP-faults on the call - after control has left our code, where
  `catch(...)` can no longer reach it.
- Wrap any risky operation (anything that calls into game code) in `try/catch`. The
  build uses `/EHa`, so `catch(...)` also traps access violations.
- Do not run structural or heavy work on the render (Present) thread. Use the
  worker thread or the game-thread pump, the way the existing features do. This
  covers more than it looks: `K2_SetActorLocation` is not a property write but a
  full component move (scene transform, physics body, overlap refresh that can fire
  blueprint delegates, streaming and significance updates), and moving an actor from
  the Present hook races the game thread over the same actor graph. `bSweep=true`
  adds a blocking-hit query on top, which can call `OnComponentHit` into blueprint
  code. It also silently breaks calls that depend on engine bookkeeping -
  `SetMovementMode` from the render thread returns having done nothing.
- Never detour an address that is not a **function entry**. Guard every MinHook
  target with `Scanner::IsFunctionEntry`, not `Scanner::IsExecutableAddress`, which
  is true of every byte in `.text` including the middle of an instruction. MinHook
  writes its 5-byte JMP wherever it is told: an RVA that a game patch has shifted
  lands mid-instruction and rewrites the game's own code. That is not a read of
  garbage, it is corruption of the game, and it surfaces later as a crash in game
  code with nothing of ours on the stack (see issue #3).
- Re-validate cached actors immediately before each `ProcessEvent`; they can go
  stale between frames. Use `UE::IsLiveObject` (or `UE::IsLiveObjectNamed` when the
  cache is keyed by name) - **not** `Mem::IsReadable`, which cannot answer this.
  Destroying a `UObject` does not unmap its memory, so a dead object stays readable
  and its fields return whatever now occupies the recycled block.
- Do not reintroduce the native nav / behavior-tree calls that were deliberately
  removed for crashing.

## Offsets and SDK

- Build-specific offsets live in `src/sdk/offsets.h`. Document where each value
  came from in the dumped SDK, the way the existing entries do.
- Use the full `/Script/...` names for functions, or `FindFunctionInClass` for
  blueprint-mounted classes.
- Prefer deriving a native hook target by **signature** (see `src/hooks/native_hooks.cpp`)
  over hardcoding an RVA. A hardcoded RVA is correct only for the build it was read
  from, and it fails destructively rather than quietly - see the detour rule above.
  If you must hardcode one, add it to `kNativeHookRvas` in `features.cpp` so the
  injection-time self-check reports it as stale after a patch.
- After a game patch, press **Debug -> Verify member offsets** before trusting
  anything in `Offsets::AH`. It reads each reflected member offset and each
  ProcessEvent params-struct size off the running game and names what moved.

## Documentation

- Project rule: when you change code or behavior, update `README.md` **and**
  `PROJECT_AND_SDK.md` in the same pull request so the docs do not go stale.
- Docs style: plain hyphens only. No em dashes or en dashes.

## Commit messages

- Use the imperative mood in the subject ("Add fly speed slider", not "Added" or
  "Adds").
- Keep the subject under about 72 characters, capitalized, with no trailing period.
- Leave a blank line, then a body that explains **what** changed and **why**, not
  just how.
- Reference issues in the body or footer (for example, "Fixes #12").
- Keep each commit a single coherent change. Do not mix unrelated edits.

## Pull requests

- Branch from `main` with a short, descriptive name (for example
  `feature/object-spawn` or `fix/ammo-restore`).
- Fill in the pull request template.
- State exactly what you tested: which game build, and what you verified in-game.
- Make sure it compiles in Release and adds no new warnings.
- Keep the diff minimal and on-topic. No drive-by reformatting of unrelated code.

## Issues

- Use the issue templates.
- **Bug reports** must include your game version/build, steps to reproduce, what
  you expected, what happened, and the `AtomicHeartMenu.log` file. Logs are the
  single most useful thing you can attach.
- **Feature requests** should describe the use case, not just the feature.
