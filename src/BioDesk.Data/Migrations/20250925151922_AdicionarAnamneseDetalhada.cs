using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class AdicionarAnamneseDetalhada : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AlergiasConhecidas",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 1000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AntecedentesFamiliares",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 3000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AtividadeFisica",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 1000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "CirurgiasRealizadas",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ConsumoAlcoolEnum",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 50,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "DoencasAnteriores",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "DoencasHereditarias",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "DuracaoSintomas",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "FatoresDesencadeantes",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "GestaoStress",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "HabitosAlimentares",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "HistoriaDoencaAtual",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 3000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "IntensidadeSintomas",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 20,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "QualidadeDesonoEnum",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 50,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "QueixaPrincipal",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SistemaCardiovascular",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SistemaDigestivo",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SistemaNeurologico",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SistemaRespiratorio",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Tabagismo",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 50,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TratamentosRealizados",
                table: "Pacientes",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 11, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393), new DateTime(2025, 9, 11, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 18, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393), new DateTime(2025, 9, 18, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 15, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393), new DateTime(2025, 9, 15, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 27, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393), new DateTime(2025, 9, 22, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "AlergiasConhecidas", "AntecedentesFamiliares", "AtividadeFisica", "AtualizadoEm", "CirurgiasRealizadas", "ConsumoAlcoolEnum", "CriadoEm", "DoencasAnteriores", "DoencasHereditarias", "DuracaoSintomas", "FatoresDesencadeantes", "GestaoStress", "HabitosAlimentares", "HistoriaDoencaAtual", "IntensidadeSintomas", "QualidadeDesonoEnum", "QueixaPrincipal", "SistemaCardiovascular", "SistemaDigestivo", "SistemaNeurologico", "SistemaRespiratorio", "Tabagismo", "TratamentosRealizados" },
                values: new object[] { null, null, null, new DateTime(2025, 9, 23, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393), null, null, new DateTime(2025, 8, 26, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393), null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "AlergiasConhecidas", "AntecedentesFamiliares", "AtividadeFisica", "AtualizadoEm", "CirurgiasRealizadas", "ConsumoAlcoolEnum", "CriadoEm", "DoencasAnteriores", "DoencasHereditarias", "DuracaoSintomas", "FatoresDesencadeantes", "GestaoStress", "HabitosAlimentares", "HistoriaDoencaAtual", "IntensidadeSintomas", "QualidadeDesonoEnum", "QueixaPrincipal", "SistemaCardiovascular", "SistemaDigestivo", "SistemaNeurologico", "SistemaRespiratorio", "Tabagismo", "TratamentosRealizados" },
                values: new object[] { null, null, null, new DateTime(2025, 9, 20, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393), null, null, new DateTime(2025, 8, 31, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393), null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "AlergiasConhecidas", "AntecedentesFamiliares", "AtividadeFisica", "AtualizadoEm", "CirurgiasRealizadas", "ConsumoAlcoolEnum", "CriadoEm", "DoencasAnteriores", "DoencasHereditarias", "DuracaoSintomas", "FatoresDesencadeantes", "GestaoStress", "HabitosAlimentares", "HistoriaDoencaAtual", "IntensidadeSintomas", "QualidadeDesonoEnum", "QueixaPrincipal", "SistemaCardiovascular", "SistemaDigestivo", "SistemaNeurologico", "SistemaRespiratorio", "Tabagismo", "TratamentosRealizados" },
                values: new object[] { null, null, null, new DateTime(2025, 9, 24, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393), null, null, new DateTime(2025, 9, 5, 16, 19, 21, 619, DateTimeKind.Local).AddTicks(1393), null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AlergiasConhecidas",
                table: "Pacientes");

            migrationBuilder.DropColumn(
                name: "AntecedentesFamiliares",
                table: "Pacientes");

            migrationBuilder.DropColumn(
                name: "AtividadeFisica",
                table: "Pacientes");

            migrationBuilder.DropColumn(
                name: "CirurgiasRealizadas",
                table: "Pacientes");

            migrationBuilder.DropColumn(
                name: "ConsumoAlcoolEnum",
                table: "Pacientes");

            migrationBuilder.DropColumn(
                name: "DoencasAnteriores",
                table: "Pacientes");

            migrationBuilder.DropColumn(
                name: "DoencasHereditarias",
                table: "Pacientes");

            migrationBuilder.DropColumn(
                name: "DuracaoSintomas",
                table: "Pacientes");

            migrationBuilder.DropColumn(
                name: "FatoresDesencadeantes",
                table: "Pacientes");

            migrationBuilder.DropColumn(
                name: "GestaoStress",
                table: "Pacientes");

            migrationBuilder.DropColumn(
                name: "HabitosAlimentares",
                table: "Pacientes");

            migrationBuilder.DropColumn(
                name: "HistoriaDoencaAtual",
                table: "Pacientes");

            migrationBuilder.DropColumn(
                name: "IntensidadeSintomas",
                table: "Pacientes");

            migrationBuilder.DropColumn(
                name: "QualidadeDesonoEnum",
                table: "Pacientes");

            migrationBuilder.DropColumn(
                name: "QueixaPrincipal",
                table: "Pacientes");

            migrationBuilder.DropColumn(
                name: "SistemaCardiovascular",
                table: "Pacientes");

            migrationBuilder.DropColumn(
                name: "SistemaDigestivo",
                table: "Pacientes");

            migrationBuilder.DropColumn(
                name: "SistemaNeurologico",
                table: "Pacientes");

            migrationBuilder.DropColumn(
                name: "SistemaRespiratorio",
                table: "Pacientes");

            migrationBuilder.DropColumn(
                name: "Tabagismo",
                table: "Pacientes");

            migrationBuilder.DropColumn(
                name: "TratamentosRealizados",
                table: "Pacientes");

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 11, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889), new DateTime(2025, 9, 11, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 18, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889), new DateTime(2025, 9, 18, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 15, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889), new DateTime(2025, 9, 15, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 27, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889), new DateTime(2025, 9, 22, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 23, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889), new DateTime(2025, 8, 26, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 20, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889), new DateTime(2025, 8, 31, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 24, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889), new DateTime(2025, 9, 5, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889) });
        }
    }
}
