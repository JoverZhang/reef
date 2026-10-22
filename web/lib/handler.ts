import "server-only";
import { bootstrap } from "../generated/bootstrap";
import { loadSnapshot } from "./runtime";
import { subscriptionService } from "./service";

export const { serve, refresh, rules } = subscriptionService(bootstrap, loadSnapshot);
