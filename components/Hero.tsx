export default function Hero() {
  return (
    <section className="bg-gradient-to-br from-black via-slate-900 to-indigo-950 text-white min-h-screen flex items-center justify-center">

      <div className="text-center">

        <h1 className="text-7xl font-bold mb-6">

          AegisAI

        </h1>

        <p className="text-xl text-gray-300 mb-10">

          Analyse intelligente de la sécurité de vos applications web.

        </p>

        <a
          href="/dashboard"
          className="bg-cyan-500 hover:bg-cyan-400 px-8 py-4 rounded-xl text-lg"
        >

          Commencer gratuitement

        </a>

      </div>

    </section>
  );
}
