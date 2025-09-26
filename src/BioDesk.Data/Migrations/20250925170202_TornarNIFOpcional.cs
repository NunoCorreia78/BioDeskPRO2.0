using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class TornarNIFOpcional : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "NIF",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 9,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "TEXT",
                oldMaxLength: 9);

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 11, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138), new DateTime(2025, 9, 11, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 18, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138), new DateTime(2025, 9, 18, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 15, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138), new DateTime(2025, 9, 15, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 27, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138), new DateTime(2025, 9, 22, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 23, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138), new DateTime(2025, 8, 26, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 20, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138), new DateTime(2025, 8, 31, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 24, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138), new DateTime(2025, 9, 5, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138) });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "NIF",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 9,
                nullable: false,
                defaultValue: "",
                oldClrType: typeof(string),
                oldType: "TEXT",
                oldMaxLength: 9,
                oldNullable: true);

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 11, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427), new DateTime(2025, 9, 11, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 18, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427), new DateTime(2025, 9, 18, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 15, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427), new DateTime(2025, 9, 15, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 27, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427), new DateTime(2025, 9, 22, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 23, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427), new DateTime(2025, 8, 26, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 20, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427), new DateTime(2025, 8, 31, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 24, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427), new DateTime(2025, 9, 5, 17, 20, 52, 246, DateTimeKind.Local).AddTicks(3427) });
        }
    }
}
