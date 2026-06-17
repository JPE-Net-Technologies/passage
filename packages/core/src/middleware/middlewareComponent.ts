import {logger} from "../utils/logger";
import express from "express";

export default abstract class MiddlewareComponent {
  protected constructor() {
    logger.info(`MiddlewareComponent initialized`);
  }

  /**
   * Mounts the middleware component into the Express application.
   * @param app The Express application instance.
   * @returns A boolean indicating whether the middleware was mounted successfully.
   */
  abstract mount(app: express.Application): boolean;
}
