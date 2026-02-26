import { PieChart, Pie, Tooltip, Legend, ResponsiveContainer, Cell } from "recharts";
import { Order, Product } from "../types/index";

interface OrderPieChartProps {
  orders: Order[];
}

interface ChartData {
  name: string;
  value: number;
}

interface Props {
  products: Product[];
}

function generateColor(index: number) {
  const goldenAngle = 137.508;
  const hue = (index * goldenAngle) % 360;
  return `hsl(${hue}, 70%, 50%)`;
}

const COLORS = ["#3B82F6",  "#c0e41f", "#22C55E", "#EF4444"]; 

export default function OrderPieChart({ orders }: OrderPieChartProps) {
  const statusCount: Record<string, number> = orders.reduce(
    (acc, order) => {
      acc[order.status] = (acc[order.status] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  const data: ChartData[] = Object.entries(statusCount).map(
    ([key, value]) => ({
      name: key,
      value,
    })
  );

  if (!orders.length) return <p>No orders found</p>;

  return (
    <div style={{ width: "100%", height: 300 }}>
      <ResponsiveContainer>
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            outerRadius={110}
          >
            {data.map((_, index) => (
              <Cell
                key={`cell-${index}`}
                fill={COLORS[index % COLORS.length]}
              />
            ))}
          </Pie>
          <Tooltip />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

export function ProductCategoryChart({ products }: Props) {
  const categoryData = Object.values(
    products.reduce((acc: any, product) => {
      acc[product.category] = acc[product.category] || {
        name: product.category,
        value: 0
      };
      acc[product.category].value += 1;
      return acc;
    }, {})
  );

  return (
    <div className="w-full h-80">
      <ResponsiveContainer>
        <PieChart>
          <Pie
            data={categoryData}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            outerRadius={110}
          >
            {categoryData.map((entry: any, index) => (
              <Cell
                key={entry.name}
                fill={generateColor(index)}
              />
            ))}
          </Pie>
          <Tooltip />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}