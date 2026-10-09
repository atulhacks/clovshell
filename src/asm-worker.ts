import { assemble, disassemble, initEngines } from './engines';
import type { AssembleResult } from './engines';

interface Request {
  archId: string;
  source: string;
  baseURI: string;
}

type Response = { result: AssembleResult; insnCount: number } | { error: string };

const scope = self as unknown as {
  onmessage: ((event: MessageEvent<Request>) => void) | null;
  postMessage(message: Response): void;
};

scope.onmessage = (event) => {
  const { archId, source, baseURI } = event.data;
  void initEngines(undefined, baseURI)
    .then(() => {
      const result = assemble(archId, source);
      const decoded = result.bytes ? disassemble(archId, result.bytes) : null;
      const insnCount = decoded?.ok ? decoded.insns.length : 0;
      scope.postMessage({ result, insnCount });
    })
    .catch((error: unknown) => scope.postMessage({
      error: error instanceof Error ? error.message : String(error),
    }));
};
