export default function Home() {
  return (
    <div className="max-w-4xl mx-auto">
      <div className="text-center">
        <h1 className="text-4xl font-bold text-gray-900 mb-6">
          Welcome to Next.js Auth App
        </h1>
        <p className="text-xl text-gray-600 mb-8">
          A complete authentication system with JWT tokens and MongoDB
        </p>
        <div className="space-x-4">
          <a
            href="/login"
            className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
          >
            Login
          </a>
          <a
            href="/signup"
            className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded"
          >
            Sign Up
          </a>
        </div>
      </div>
    </div>
  );
}