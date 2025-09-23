import React from 'react';

export default function UserWelcome() {
  return (
    <div className="flex justify-center items-center h-screen">
      <div className="card w-96 bg-base-100 shadow-xl">
        <div className="card-body flex flex-col items-center">
          <h2 className="card-title">Welcome!</h2>
          <p>You have successfully logged in as a regular user.</p>
        </div>
      </div>
    </div>
  );
}
