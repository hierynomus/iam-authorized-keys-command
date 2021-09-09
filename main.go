// This code is taken from https://github.com/Fullscreen/iam-authorized-keys-command
// Its responsibility is to query iam service for users that match criteria, and list them with ssh public keys
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type Config struct {
	IAMGroup    string
	AWSProfile  string
	SSHUsername string
}

type UserKey struct {
	Username string
	PubKey   string
}

type IAMKeyFetcher struct {
	ctx    context.Context
	config *Config
	wg     *sync.WaitGroup

	userCh chan<- *UserKey
	errCh  chan<- error
	doneCh chan<- bool
}

func (u *UserKey) String() string {
	return fmt.Sprintf("# %s\n%s\n", u.Username, u.PubKey)
}

const (
	exitCodeOk    int = 0
	exitCodeError int = 1
)

var (
	cfg       = &Config{}
	verbosity int

	cmd = &cobra.Command{
		Use:  "iam-authorized-keys",
		RunE: FetchIAMUsers,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			switch verbosity {
			case 0:
				// Nothing to do
			case 1:
				zerolog.SetGlobalLevel(zerolog.InfoLevel)
			case 2: //nolint:gomnd
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			default:
				zerolog.SetGlobalLevel(zerolog.TraceLevel)
			}

			return nil
		},
	}
)

func main() {
	ctx := context.Background()
	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	l := log.Output(os.Stderr)
	ctx = l.WithContext(ctx)
	cmd.Flags().StringVarP(&cfg.IAMGroup, "iam-group", "i", "", "Get SSH keys from this IAM group")
	cmd.Flags().StringVarP(&cfg.AWSProfile, "aws-profile", "p", "", "Connect to the specified AWS profile")
	cmd.Flags().CountVarP(&verbosity, "verbose", "v", "Print more verbose logging")
	cmd.ExecuteContext(ctx)
}

// The main function of the Root command
func FetchIAMUsers(cmd *cobra.Command, args []string) error {
	// Handle SIGPIPE
	//
	// When sshd identifies a key in the stdout of this command, it closes
	// the pipe causing a series of EPIPE errors before a SIGPIPE is emitted
	// on this scripts pid. If the script exits with the standard 13 code, sshd
	// will disregard any matched keys. We catch the signal here and exit 0 to
	// fix that problem.
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGPIPE)
	userCh := make(chan *UserKey)
	errCh := make(chan error)
	doneCh := make(chan bool)

	ctx := cmd.Context()
	f := &IAMKeyFetcher{
		ctx:    ctx,
		config: cfg,
		wg:     &sync.WaitGroup{},
		userCh: userCh,
		errCh:  errCh,
		doneCh: doneCh,
	}

	log.Info().Msg("Starting IAM Fetch")

	go f.Fetch()

	for {
		select {
		case _ = <-c:
			os.Exit(exitCodeOk)
		case err := <-errCh:
			log.Ctx(ctx).Error().Err(err).Msg("Error occurred")
			os.Exit(exitCodeError)
		case userKey := <-userCh:
			fmt.Print(userKey)
		case <-doneCh:
			os.Exit(exitCodeOk)
		}
	}
}

func (ikf *IAMKeyFetcher) Fetch() {
	log.Ctx(ikf.ctx).Debug().Msg("Started IAM Key Fetcher")
	awsConfig, err := config.LoadDefaultConfig(ikf.ctx)

	if err != nil {
		ikf.errCh <- err
		return
	}

	svc := iam.NewFromConfig(awsConfig)

	users, err := ikf.listUsers(ikf.ctx, svc, cfg.IAMGroup)
	if err != nil {
		ikf.errCh <- err
		return
	}

	log.Ctx(ikf.ctx).Debug().Interface("users", users).Msg("Fetched users")

	for _, u := range users {
		ikf.wg.Add(1)
		go ikf.fetchPubKey(ikf.ctx, svc, *u.UserName)
	}
	ikf.wg.Wait()
	ikf.doneCh <- true
	close(ikf.userCh)
}

// Fetch the public key for the user
func (ikf *IAMKeyFetcher) fetchPubKey(ctx context.Context, svc *iam.Client, user string) {
	params := &iam.ListSSHPublicKeysInput{
		UserName: &user,
	}

	log.Ctx(ikf.ctx).Debug().Str("username", user).Msg("Fetching keys")

	if resp, err := svc.ListSSHPublicKeys(ikf.ctx, params); err == nil {
		for _, k := range resp.SSHPublicKeys {
			if k.Status != types.StatusTypeActive {
				continue
			}

			params := &iam.GetSSHPublicKeyInput{
				Encoding:       types.EncodingTypeSsh,
				SSHPublicKeyId: k.SSHPublicKeyId,
				UserName:       &user,
			}

			resp, err := svc.GetSSHPublicKey(ikf.ctx, params)
			if err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
			}

			ikf.userCh <- &UserKey{
				Username: user,
				PubKey:   *resp.SSHPublicKey.Fingerprint,
			}
		}
	} else {
		fmt.Fprintln(os.Stderr, err.Error())
	}
	ikf.wg.Done()
}

// get all IAM users, or just those that are part of the defined group
func (ikf *IAMKeyFetcher) listUsers(ctx context.Context, svc *iam.Client, iamGroup string) ([]types.User, error) {
	if iamGroup != "" {
		params := &iam.GetGroupInput{
			GroupName: aws.String(iamGroup),
			MaxItems:  aws.Int32(1000),
		}

		resp, err := svc.GetGroup(ctx, params)
		if err != nil {
			return nil, err
		}

		return resp.Users, nil
	}

	params := &iam.ListUsersInput{
		MaxItems: aws.Int32(1000),
	}

	resp, err := svc.ListUsers(ctx, params)
	if err != nil {
		return nil, err
	}

	return resp.Users, nil
}
