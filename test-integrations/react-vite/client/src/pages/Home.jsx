const Home = () => {
    return (
      <div>
        <h1>Welcome</h1>
        <p>This is the home page that's accessible to everyone.</p>
        <p>Other menu options will show up when the user is authenticated.</p>
        <p>/protected: authenticated users only</p>
        <p>/managers: authenticated users who are members of the group 'manager'</p>
      </div>
    )
  }
  
  export default Home