export default function Navbar() {
  return (
    <nav className="w-full bg-black text-white px-8 py-5 flex justify-between">
      <h1 className="text-2xl font-bold text-cyan-400">
        AegisAI
      </h1>

      <div className="space-x-5">
        <a href="/">Accueil</a>
        <a href="/pricing">Tarifs</a>
        <a href="/dashboard">Dashboard</a>
        <a href="/login">Connexion</a>
      </div>
    </nav>
  );
}
