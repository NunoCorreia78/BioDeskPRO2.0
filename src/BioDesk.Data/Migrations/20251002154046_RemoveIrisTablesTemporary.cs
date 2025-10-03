using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class RemoveIrisTablesTemporary : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 2, 15, 40, 44, 844, DateTimeKind.Utc).AddTicks(7955));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 17, 15, 40, 44, 844, DateTimeKind.Utc).AddTicks(7966));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 25, 15, 40, 44, 844, DateTimeKind.Utc).AddTicks(7971));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 2, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8468), new DateTime(2025, 9, 2, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8458) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 9, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8479), new DateTime(2025, 9, 9, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8475) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 22, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8491), new DateTime(2025, 9, 22, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8486) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 17, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8503), new DateTime(2025, 9, 17, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8497) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 1, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8514), new DateTime(2025, 10, 1, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8509) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 27, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8528), new DateTime(2025, 9, 27, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8520) });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 2, 11, 12, 39, 719, DateTimeKind.Utc).AddTicks(9416));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 17, 11, 12, 39, 719, DateTimeKind.Utc).AddTicks(9432));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 25, 11, 12, 39, 719, DateTimeKind.Utc).AddTicks(9437));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 2, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(42), new DateTime(2025, 9, 2, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(27) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 9, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(52), new DateTime(2025, 9, 9, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(48) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 22, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(62), new DateTime(2025, 9, 22, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(57) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 17, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(73), new DateTime(2025, 9, 17, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(68) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 1, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(83), new DateTime(2025, 10, 1, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(79) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 27, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(94), new DateTime(2025, 9, 27, 12, 12, 39, 720, DateTimeKind.Local).AddTicks(90) });
        }
    }
}
