import random
import xlsxwriter
import pandas as pd
import matplotlib.pyplot as plt


def trust_equation(alpha, time_now, delta_time, trust):
    result = (1 - alpha) * abs(time_now - delta_time) * 0.99 + (alpha * trust * 0.01)

    return result if result < 1 else (result * random.uniform(0.9, 0.95)) / result


def write_to_workbook(index):

    workbook = xlsxwriter.Workbook(f"node_data_{index}.xlsx")
    worksheet = workbook.add_worksheet()

    gap: float = 0.0
    second: int = 0.0
    alpha: float = random.uniform(0, 1)
    initial_trust: float = random.uniform(0.45, 0.6)
    to_return_trust: float = initial_trust

    for i in range(0, 100):
        worksheet.write(i, 0, initial_trust)

        case: float = random.randint(0, 1)

        if case == 1:
            gap = random.uniform(0.20, 0.30)
        else:
            gap = random.uniform(0.30, 0.50)

        initial_trust = trust_equation(
            alpha=alpha,
            time_now=gap,
            delta_time=gap + second,
            trust=initial_trust,
        )

        second = second + gap
        worksheet.write(i, 1, second)

    workbook.close()

    return to_return_trust


def generate_graph(nodes, initial_trusts):
    plt.figure(figsize=(12, 4))
    plt.xlabel("Seconds")
    plt.ylabel("Trust Value")

    for index in range(1, nodes + 1):
        dfs = pd.read_excel(f"node_data_{index}.xlsx", header=None)
        plt.errorbar(
            dfs.iloc[:, 1],
            dfs.iloc[:, 0],
            label=f"Node {index} - Trust {initial_trusts[index - 1]}",
        )

    plt.legend(loc="lower right")

    plt.savefig(f"node_data.png")


if __name__ == "__main__":

    nodes: int = 10
    initial_trusts: list = []

    for i in range(1, nodes + 1):
        initial_trusts.append(write_to_workbook(i))

    generate_graph(nodes=nodes, initial_trusts=initial_trusts)
