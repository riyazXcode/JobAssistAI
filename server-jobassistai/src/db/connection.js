import mongoose from 'mongoose';

export async function connectDB() {
  const uri = process.env.MONGO_URI;
  if (!uri) {
    console.error('Missing MONGO_URI');
    process.exit(1);
  }
  await mongoose.connect(uri, {
    autoIndex: false,
    serverSelectionTimeoutMS: 5000,
  });
  console.log('Connected to MongoDB');
}
