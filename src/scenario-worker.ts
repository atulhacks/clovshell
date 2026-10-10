import { runEmulation } from './emu';
import type { EmuResult } from './emu';

interface Request {
  archId: string;
  bytes: Uint8Array;
  args: bigint[];
  inputBytes: Uint8Array;
}

type Response = { index: number; result: EmuResult } | { index: number; error: string } | { done: true };

const scope = self as unknown as {
  onmessage: ((event: MessageEvent<Request>) => void) | null;
  postMessage(message: Response): void;
};

scope.onmessage = (event) => {
  void (async () => {
    const { archId, bytes, args, inputBytes } = event.data;
    for (const [index, entryArg] of args.entries()) {
      try {
        scope.postMessage({ index, result: await runEmulation(archId, bytes, entryArg, inputBytes) });
      } catch (error) {
        scope.postMessage({ index, error: error instanceof Error ? error.message : String(error) });
      }
    }
    scope.postMessage({ done: true });
  })();
};
