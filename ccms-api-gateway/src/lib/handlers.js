import { getGateway } from './instance.js';

// One handler for every method. Each service folder under src/app/api/ re-exports these, so the
// routes look like the file structure PDF while the checking and forwarding stay in one place.
const handle = (request) => getGateway()(request);

export const GET = handle;
export const POST = handle;
export const PUT = handle;
export const PATCH = handle;
export const DELETE = handle;
export const HEAD = handle;
export const OPTIONS = handle;
