interface Props {

    title: string;

    value: string;

    color: string;

}

export default function StatCard({

    title,

    value,

    color

}: Props) {

    return (

        <div
            className="
            rounded-xl
            bg-slate-900
            border
            border-slate-800
            p-6"
        >

            <h3 className="text-gray-400">

                {title}

            </h3>

            <h2
                className={`text-4xl font-bold mt-4 ${color}`}
            >

                {value}

            </h2>

        </div>

    )

}
