using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecureDataSharing.Data.Migrations
{
    /// <inheritdoc />
    public partial class AdaptStoredDataForFileContentInDb : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EncryptedData",
                table: "StoredDatas");

            migrationBuilder.AddColumn<string>(
                name: "ContentType",
                table: "StoredDatas",
                type: "nvarchar(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "DataType",
                table: "StoredDatas",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<byte[]>(
                name: "EncryptedContentBytes",
                table: "StoredDatas",
                type: "varbinary(max)",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "FileSize",
                table: "StoredDatas",
                type: "bigint",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "OriginalFileName",
                table: "StoredDatas",
                type: "nvarchar(255)",
                maxLength: 255,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ContentType",
                table: "StoredDatas");

            migrationBuilder.DropColumn(
                name: "DataType",
                table: "StoredDatas");

            migrationBuilder.DropColumn(
                name: "EncryptedContentBytes",
                table: "StoredDatas");

            migrationBuilder.DropColumn(
                name: "FileSize",
                table: "StoredDatas");

            migrationBuilder.DropColumn(
                name: "OriginalFileName",
                table: "StoredDatas");

            migrationBuilder.AddColumn<byte[]>(
                name: "EncryptedData",
                table: "StoredDatas",
                type: "varbinary(max)",
                nullable: false,
                defaultValue: new byte[0]);
        }
    }
}
