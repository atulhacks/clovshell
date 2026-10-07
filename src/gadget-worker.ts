import { initDisassembler } from './engines';
import { findGadgets } from './gadgets';
import type { Gadget } from './gadgets';

interface Request {
  archId: string;
  bytes: Uint8Array;
  baseURI: string;
}

type Response = { gadgets: Gadget[] } | { error: string };

const scope = self as unknown as {
  onmessage: ((event: MessageEvent<Request>) => void) | null;
  postMessage(message: Response): void;
};

scope.onmessage = (event) => {
  void initDisassembler(event.data.baseURI)
    .then(() => findGadgets(event.data.archId, event.data.bytes))
    .then((result) => {
      if (Array.isArray(result)) scope.postMessage({ gadgets: result });
      else scope.postMessage({ error: result.error });
    })
    .catch((error: unknown) => scope.postMessage({
      error: error instanceof Error ? error.message : String(error),
    }));
};
