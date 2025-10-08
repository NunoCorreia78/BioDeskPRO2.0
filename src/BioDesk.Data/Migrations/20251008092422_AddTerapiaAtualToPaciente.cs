using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddTerapiaAtualToPaciente : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<DateTime>(
                name: "DataNascimento",
                table: "Pacientes",
                type: "TEXT",
                nullable: true,
                oldClrType: typeof(DateTime),
                oldType: "TEXT");

            migrationBuilder.AddColumn<string>(
                name: "TerapiaAtual",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "DataCriacao", "TerapiaAtual" },
                values: new object[] { new DateTime(2025, 9, 8, 9, 24, 20, 865, DateTimeKind.Utc).AddTicks(1010), null });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "DataCriacao", "TerapiaAtual" },
                values: new object[] { new DateTime(2025, 9, 23, 9, 24, 20, 865, DateTimeKind.Utc).AddTicks(1021), null });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "DataCriacao", "TerapiaAtual" },
                values: new object[] { new DateTime(2025, 10, 1, 9, 24, 20, 865, DateTimeKind.Utc).AddTicks(1024), null });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 8, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1412), new DateTime(2025, 9, 8, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1399) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 15, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1421), new DateTime(2025, 9, 15, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1418) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 28, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1426), new DateTime(2025, 9, 28, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1424) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 23, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1433), new DateTime(2025, 9, 23, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1430) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 7, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1438), new DateTime(2025, 10, 7, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1436) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 3, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1443), new DateTime(2025, 10, 3, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1441) });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "TerapiaAtual",
                table: "Pacientes");

            migrationBuilder.AlterColumn<DateTime>(
                name: "DataNascimento",
                table: "Pacientes",
                type: "TEXT",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                oldClrType: typeof(DateTime),
                oldType: "TEXT",
                oldNullable: true);

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 2, 21, 11, 43, 475, DateTimeKind.Utc).AddTicks(5589));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 17, 21, 11, 43, 475, DateTimeKind.Utc).AddTicks(5599));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 25, 21, 11, 43, 475, DateTimeKind.Utc).AddTicks(5603));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 2, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(5983), new DateTime(2025, 9, 2, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(5971) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 9, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(5992), new DateTime(2025, 9, 9, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(5988) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 22, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(6000), new DateTime(2025, 9, 22, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(5996) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 17, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(6008), new DateTime(2025, 9, 17, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(6004) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 1, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(6015), new DateTime(2025, 10, 1, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(6012) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 27, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(6022), new DateTime(2025, 9, 27, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(6019) });
        }
    }
}
