using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddLastActiveTabToPaciente : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "LastActiveTab",
                table: "Pacientes",
                type: "INTEGER",
                nullable: false,
                defaultValue: 1);

            migrationBuilder.UpdateData(
                table: "ConfiguracaoClinica",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataAtualizacao",
                value: new DateTime(2025, 10, 12, 16, 47, 40, 795, DateTimeKind.Utc).AddTicks(2164));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "DataCriacao", "LastActiveTab" },
                values: new object[] { new DateTime(2025, 9, 12, 16, 47, 40, 795, DateTimeKind.Utc).AddTicks(1223), 1 });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "DataCriacao", "LastActiveTab" },
                values: new object[] { new DateTime(2025, 9, 27, 16, 47, 40, 795, DateTimeKind.Utc).AddTicks(1244), 1 });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "DataCriacao", "LastActiveTab" },
                values: new object[] { new DateTime(2025, 10, 5, 16, 47, 40, 795, DateTimeKind.Utc).AddTicks(1251), 1 });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 12, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1868), new DateTime(2025, 9, 12, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1840) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 19, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1887), new DateTime(2025, 9, 19, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1880) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 2, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1901), new DateTime(2025, 10, 2, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1896) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 27, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1957), new DateTime(2025, 9, 27, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1922) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 11, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1969), new DateTime(2025, 10, 11, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1965) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 7, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1992), new DateTime(2025, 10, 7, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1987) });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "LastActiveTab",
                table: "Pacientes");

            migrationBuilder.UpdateData(
                table: "ConfiguracaoClinica",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataAtualizacao",
                value: new DateTime(2025, 10, 9, 11, 22, 5, 862, DateTimeKind.Utc).AddTicks(8724));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 9, 11, 22, 5, 862, DateTimeKind.Utc).AddTicks(8204));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 24, 11, 22, 5, 862, DateTimeKind.Utc).AddTicks(8220));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 10, 2, 11, 22, 5, 862, DateTimeKind.Utc).AddTicks(8223));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 9, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8546), new DateTime(2025, 9, 9, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8533) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 16, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8555), new DateTime(2025, 9, 16, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8551) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 29, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8561), new DateTime(2025, 9, 29, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8559) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 24, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8612), new DateTime(2025, 9, 24, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8585) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 8, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8619), new DateTime(2025, 10, 8, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8616) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 4, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8626), new DateTime(2025, 10, 4, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8623) });
        }
    }
}
