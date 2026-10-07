import { disassemble, initDisassembler } from './engines';
import type { DisassembleResult } from './engines';

interface Request {
  archId: string;
  bytes: Uint8Array;
  baseURI: string;
}

type Response = { result: DisassembleResult } | { error: string };

const scope = self as unknown as {
  onmessage: ((event: MessageEvent<Request>) => void) | null;
  postMessage(message: Response): void;
};

scope.onmessage = (event) => {
  void initDisassembler(event.data.baseURI)
    .then(() => disassemble(event.data.archId, event.data.bytes))
    .then((result) => scope.postMessage({ result }))
    .catch((error: unknown) => scope.postMessage({
      error: error instanceof Error ? error.message : String(error),
    }));
};
