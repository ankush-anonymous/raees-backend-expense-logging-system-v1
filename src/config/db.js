import mongoose from "mongoose";

/**
 * @param {string} uri
 * @returns {Promise<typeof mongoose>}
 */
export async function connectDb(uri) {
  mongoose.set("strictQuery", true);
  await mongoose.connect(uri);
  return mongoose;
}
