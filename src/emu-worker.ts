import { runEmulation } from './emu';
import type { EmuResult } from './emu';

interface Request {
  archId: string;
  bytes: Uint8Array;
  entryArg: bigint | null;
}

type Response = { result: EmuResult } | { error: string };

const scope = self as unknown as {
  onmessage: ((event: MessageEvent<Request>) => void) | null;
  postMessage(message: Response): void;
};

scope.onmessage = (event) => {
  void runEmulation(event.data.archId, event.data.bytes, event.data.entryArg)
    .then((result) => scope.postMessage({ result }))
    .catch((error: unknown) => scope.postMessage({
      error: error instanceof Error ? error.message : String(error),
    }));
};
