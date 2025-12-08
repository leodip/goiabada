import TokenInspector from '../components/TokenInspector';

const Tokens = () => {
    return (
        <div className="page tokens-page">
            <div className="page-header">
                <h1>Token inspector</h1>
                <p className="page-description">
                    Explore the contents of your OAuth2/OIDC tokens. This is an educational
                    tool to help you understand what information is contained in each token.
                </p>
            </div>

            <TokenInspector />
        </div>
    );
};

export default Tokens;
