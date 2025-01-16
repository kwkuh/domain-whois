import { useEffect } from "react";
import { cn } from "@/lib/utils";

const Index = () => {
  useEffect(() => {
    // Redirect after 2 seconds
    const timer = setTimeout(() => {
      window.location.href = "https://kukuh.link";
    }, 2000);

    return () => clearTimeout(timer);
  }, []);

  return (
    <div className="min-h-screen flex items-center justify-center bg-white">
      <div className="text-center space-y-4 animate-fade-up">
        <div className="loading-dots flex justify-center space-x-2">
          <div className="w-3 h-3 bg-gray-800 rounded-full animate-bounce" style={{ animationDelay: "0s" }}></div>
          <div className="w-3 h-3 bg-gray-800 rounded-full animate-bounce" style={{ animationDelay: "0.2s" }}></div>
          <div className="w-3 h-3 bg-gray-800 rounded-full animate-bounce" style={{ animationDelay: "0.4s" }}></div>
        </div>
        <p className="text-gray-600 mt-4">Redirecting to kukuh.link...</p>
      </div>
    </div>
  );
};

export default Index;